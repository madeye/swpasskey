// TPM backend against swtpm. Runs only when SWPASSKEY_ITEST_TPM=1 and
// `swtpm` is on PATH (any OS with a tpm2-tss that has the swtpm TCTI).
// Generates, loads, signs (verified with OpenSSL), seals/unseals, and checks
// that the private scalar is not derivable from the persisted handle.
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "../ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

using namespace swpk;

namespace {

struct Swtpm {
  pid_t pid{-1};
  std::filesystem::path dir;
  int port{2321};
  std::string tcti() const { return "swtpm:host=127.0.0.1,port=" + std::to_string(port); }
  bool start() {
    dir = std::filesystem::temp_directory_path() / ("swpk-swtpm-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    port = 20000 + (::getpid() % 10000);
    const std::string state = "dir=" + dir.string();
    const std::string server = "type=tcp,port=" + std::to_string(port);
    const std::string ctrl = "type=tcp,port=" + std::to_string(port + 1);
    pid = ::fork();
    if (pid == 0) {
      ::execlp("swtpm", "swtpm", "socket", "--tpm2", "--tpmstate", state.c_str(), "--server",
               server.c_str(), "--ctrl", ctrl.c_str(), "--flags", "not-need-init,startup-clear",
               nullptr);
      ::_exit(127);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return pid > 0;
  }
  ~Swtpm() {
    if (pid > 0) {
      ::kill(pid, SIGTERM);
      int st = 0;
      ::waitpid(pid, &st, 0);
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
  }
};

bool enabled() {
  const char* e = std::getenv("SWPASSKEY_ITEST_TPM");
  return e != nullptr && std::string(e) == "1" &&
         std::system("command -v swtpm >/dev/null 2>&1") == 0;
}

}  // namespace

TEST_CASE("TPM2 backend against swtpm: generate/load/sign/seal", "[tpm][itest]") {
  if (!enabled()) {
    WARN("SWPASSKEY_ITEST_TPM=1 not set or swtpm missing; skipping");
    return;
  }
  Swtpm tpm;
  REQUIRE(tpm.start());
  crypto::Provider p;
  crypto::Tpm2Params params;
  REQUIRE(p.random(params.srk_unique_seed).has_value());
  REQUIRE(p.random(params.object_auth).has_value());
  crypto::ProbeOptions opt;
  opt.pref = "tpm";
  opt.tpm_tcti = tpm.tcti();
  opt.tpm_params = [&]() -> Result<crypto::Tpm2Params> { return params; };
  std::string why;
  auto b = crypto::make_tpm2_key_backend(opt, why);
  INFO(why);
  REQUIRE(b != nullptr);
  REQUIRE(b->kind() == crypto::BackendKind::Tpm2);

  auto key = b->generate();
  REQUIRE(key.has_value());
  REQUIRE((*key)->kind() == crypto::BackendKind::Tpm2);
  auto handle = (*key)->persist_handle();
  REQUIRE(handle.size() > 100);
  const auto pub = (*key)->pub();
  const std::uint8_t msg[] = "authData||clientDataHash";
  auto sig = (*key)->sign_der(msg);
  REQUIRE(sig.has_value());
  REQUIRE(test::verify_es256(pub, msg, *sig));

  // Reload from the persisted blob (fresh SigningKey), sign again.
  auto loaded = b->load(handle, pub);
  REQUIRE(loaded.has_value());
  auto sig2 = (*loaded)->sign_der(msg);
  REQUIRE(sig2.has_value());
  REQUIRE(test::verify_es256(pub, msg, *sig2));
  // Wrong pub → InvalidCredential; corrupt blob → error.
  crypto::P256PublicKey wrong = pub;
  wrong.x[0] ^= 1;
  REQUIRE(b->load(handle, wrong).error() == Status::InvalidCredential);
  auto corrupt = handle;
  corrupt[corrupt.size() / 2] ^= 0xFF;
  auto cl = b->load(corrupt, pub);
  if (cl.has_value()) {
    REQUIRE_FALSE((*cl)->sign_der(msg).has_value());
  }

  // Seal / unseal a 64-byte credRandom.
  std::array<std::uint8_t, 64> secret{};
  REQUIRE(p.random(secret).has_value());
  auto wrapped = b->wrap_secret(secret);
  REQUIRE(wrapped.has_value());
  REQUIRE(std::string(wrapped->begin(), wrapped->end()).find(std::string(secret.begin(), secret.end())) == std::string::npos);
  auto un = b->unwrap_secret(*wrapped);
  REQUIRE(un.has_value());
  REQUIRE(std::vector<std::uint8_t>(secret.begin(), secret.end()) == *un);

  // A second backend instance with the SAME seed loads the blob; a DIFFERENT
  // seed (new primary) cannot.
  auto b2 = crypto::make_tpm2_key_backend(opt, why);
  REQUIRE(b2 != nullptr);
  auto l2 = b2->load(handle, pub);
  REQUIRE(l2.has_value());
  REQUIRE((*l2)->sign_der(msg).has_value());
  crypto::Tpm2Params other = params;
  other.srk_unique_seed[0] ^= 1;
  opt.tpm_params = [&]() -> Result<crypto::Tpm2Params> { return other; };
  auto b3 = crypto::make_tpm2_key_backend(opt, why);
  REQUIRE(b3 != nullptr);
  auto l3 = b3->load(handle, pub);
  if (l3.has_value()) {
    REQUIRE_FALSE((*l3)->sign_der(msg).has_value());
  }
  REQUIRE_FALSE(b3->unwrap_secret(*wrapped).has_value());
}

TEST_CASE("TPM2 backend end to end through the authenticator", "[tpm][itest]") {
  if (!enabled()) {
    WARN("SWPASSKEY_ITEST_TPM=1 not set or swtpm missing; skipping");
    return;
  }
  Swtpm tpm;
  REQUIRE(tpm.start());
  crypto::Provider p;
  auto store = store::CredentialStore::open_memory();
  crypto::ProbeOptions opt;
  opt.pref = "tpm";
  opt.tpm_tcti = tpm.tcti();
  opt.tpm_params = [&]() -> Result<crypto::Tpm2Params> {
    auto t = store->tpm_state_or_create(p);
    if (!t) return std::unexpected(t.error());
    return crypto::Tpm2Params{t->srk_unique_seed, t->object_auth};
  };
  std::string why;
  auto hw = crypto::make_tpm2_key_backend(opt, why);
  REQUIRE(hw != nullptr);
  crypto::SoftwareKeyBackend sw;
  test::ScriptedPresence presence;
  ctap::AuthenticatorConfig cfg;
  ctap::Authenticator auth(cfg, p, *hw, sw, *store, presence);
  ctap::CancelToken tok;
  auto r = auth.handle_cbor(test::make_cred_request({}), tok);
  REQUIRE(r.has_value());
  auto m = test::split_int_map(*r);
  auto ad = test::parse_auth_data(test::as_bstr(m[2]));
  auto row = store->find_by_id(ad.cred_id);
  REQUIRE(row->backend == crypto::BackendKind::Tpm2);
  REQUIRE(row->priv.empty());
  REQUIRE(row->handle.size() > 100);
  REQUIRE(row->cred_random.size() > 64);  // sealed blob, not the plaintext
  test::GetAssertOpts g;
  auto a = auth.handle_cbor(test::get_assert_request(g), tok);
  REQUIRE(a.has_value());
  auto am = test::split_int_map(*a);
  auto sig = test::as_bstr(am[3]);
  auto auth_data = test::as_bstr(am[2]);
  std::vector<std::uint8_t> msg(auth_data);
  msg.insert(msg.end(), g.client_data_hash.begin(), g.client_data_hash.end());
  REQUIRE(test::verify_es256(ad.pub, msg, sig));
  REQUIRE(std::string(auth.primary_backend_name()) == "tpm2");
}
