#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/store/file_store.hpp"
#include "swpasskey/store/keychain.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace swpk;
using namespace swpk::store;

namespace {

std::filesystem::path tmpdir() {
  auto p = std::filesystem::temp_directory_path() /
           ("swpk-store-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()));
  std::filesystem::create_directories(p);
  return p;
}

Credential sw_cred(crypto::Provider& p, std::uint8_t tag) {
  crypto::SoftwareKeyBackend b;
  auto k = b.generate();
  Credential c;
  c.rp_id = "example.com";
  c.rp_id_hash = p.sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("example.com"), 11));
  c.rp_name = "Example";
  c.user_id = {tag};
  c.user_name = "u" + std::to_string(tag);
  c.user_display = "User";
  c.cred_id.fill(tag);
  c.backend = crypto::BackendKind::Software;
  auto sc = crypto::SoftwareKeyBackend::export_scalar_for_store(**k);
  c.priv.assign(sc->begin(), sc->end());
  c.pub = (*k)->pub();
  c.sign_count = 3;
  c.created_unix = 1700000000;
  c.last_used_unix = 1700000001;
  c.cred_random.assign(64, tag);
  return c;
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void write_all(const std::filesystem::path& p, const std::vector<std::uint8_t>& v) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
}

}  // namespace

TEST_CASE("store invariants: HW row with priv / software row with handle rejected", "[store]") {
  crypto::Provider p;
  auto s = CredentialStore::open_memory();
  auto c = sw_cred(p, 1);
  REQUIRE(s->put(c).has_value());
  auto bad = sw_cred(p, 2);
  bad.backend = crypto::BackendKind::Tpm2;
  bad.handle = {1, 2, 3};
  REQUIRE(s->put(bad).error() == Status::InvalidParameter);  // priv non-empty on HW
  bad.priv.clear();
  REQUIRE(s->put(bad).has_value());
  auto bad2 = sw_cred(p, 3);
  bad2.handle = {9};
  REQUIRE(s->put(bad2).error() == Status::InvalidParameter);  // handle on software
  auto bad3 = sw_cred(p, 4);
  bad3.priv.resize(31);
  REQUIRE(s->put(bad3).error() == Status::InvalidParameter);
  REQUIRE(s->count_by_backend() == std::array<std::size_t, 3>{1, 1, 0});
}

TEST_CASE("serialize/parse round trip preserves every field", "[store]") {
  crypto::Provider p;
  auto s = CredentialStore::open_memory();
  auto c = sw_cred(p, 7);
  REQUIRE(s->put(c).has_value());
  auto hw = sw_cred(p, 8);
  hw.backend = crypto::BackendKind::SecureEnclave;
  hw.priv.clear();
  hw.handle = {'t', 'a', 'g'};
  REQUIRE(s->put(hw).has_value());
  REQUIRE(s->set_pin(PinState{std::array<std::uint8_t, 16>{1, 2, 3}, 5}).has_value());
  REQUIRE(s->tpm_state_or_create(p).has_value());
  REQUIRE(s->set_u2f_attestation(U2fAttestation{{1, 2}, {3, 4, 5}}).has_value());
  REQUIRE(s->set_serial("0123456789abcdef").has_value());
  s->set_install_id({9, 9, 9});
  auto pt = s->serialize();

  auto s2 = CredentialStore::open_with(pt, nullptr);
  REQUIRE(s2.has_value());
  REQUIRE((*s2)->size() == 2);
  auto r = (*s2)->find_by_id(c.cred_id);
  REQUIRE(r.has_value());
  REQUIRE(r->rp_id == c.rp_id);
  REQUIRE(r->rp_id_hash == c.rp_id_hash);
  REQUIRE(r->rp_name == "Example");
  REQUIRE(r->user_id == c.user_id);
  REQUIRE(r->user_name == c.user_name);
  REQUIRE(r->user_display == "User");
  REQUIRE(r->backend == crypto::BackendKind::Software);
  REQUIRE(r->priv == c.priv);
  REQUIRE(r->pub.x == c.pub.x);
  REQUIRE(r->pub.y == c.pub.y);
  REQUIRE(r->sign_count == 3);
  REQUIRE(r->created_unix == 1700000000);
  REQUIRE(r->last_used_unix == 1700000001);
  REQUIRE(r->cred_random == c.cred_random);
  auto h = (*s2)->find_by_id(hw.cred_id);
  REQUIRE(h->backend == crypto::BackendKind::SecureEnclave);
  REQUIRE(h->handle == hw.handle);
  REQUIRE(h->priv.empty());
  REQUIRE((*s2)->pin().hash.has_value());
  REQUIRE((*s2)->pin().retries == 5);
  auto t = (*s2)->tpm_state_or_create(p);
  REQUIRE(t->present);
  REQUIRE(t->srk_unique_seed == s->tpm_state_or_create(p)->srk_unique_seed);
  REQUIRE((*s2)->u2f_attestation()->cert_der == std::vector<std::uint8_t>{3, 4, 5});
  REQUIRE((*s2)->serial() == "0123456789abcdef");
  REQUIRE((*s2)->install_id()[0] == 9);
  // Unknown keys are skipped (forward compatibility): append nothing, but
  // corrupt input is rejected.
  REQUIRE_FALSE(CredentialStore::open_with(std::vector<std::uint8_t>{0xA1, 0x61, 0x78}, nullptr).has_value());
}

TEST_CASE("file store: create, reopen, tamper, missing DEK", "[store][file]") {
  crypto::Provider p;
  auto d = tmpdir();
  const auto path = d / "credentials.bin";
  MemoryKeychain kc;
  std::array<std::uint8_t, 16> install_id{};
  {
    auto s = open_file_store(path, p, kc);
    REQUIRE(s.has_value());
    REQUIRE((*s)->size() == 0);
    REQUIRE(std::filesystem::exists(path));
    struct stat st{};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    REQUIRE((st.st_mode & 0777) == 0600);
    install_id = (*s)->install_id();
    REQUIRE((*s)->put(sw_cred(p, 1)).has_value());
    REQUIRE((*s)->set_serial("abcdefabcdefabcd").has_value());
    std::array<std::uint8_t, 32> nope{};
    nope.fill(2);
    REQUIRE_FALSE((*s)->update_count_and_used(nope, 42, 5).has_value());
  }
  auto raw = read_all(path);
  REQUIRE(raw.size() > 40);
  REQUIRE(std::string(raw.begin(), raw.begin() + 4) == "SWPK");
  REQUIRE(raw[4] == 1);
  REQUIRE(std::memcmp(raw.data() + 8, install_id.data(), 16) == 0);
  // Plaintext must not appear on disk.
  const std::string hay(raw.begin(), raw.end());
  REQUIRE(hay.find("example.com") == std::string::npos);
  REQUIRE(hay.find("abcdefabcdefabcd") == std::string::npos);
  {
    auto s = open_file_store(path, p, kc);
    REQUIRE(s.has_value());
    REQUIRE((*s)->size() == 1);
    REQUIRE((*s)->serial() == "abcdefabcdefabcd");
    REQUIRE((*s)->install_id() == install_id);
    std::array<std::uint8_t, 32> one{};
    one.fill(1);
    auto c = (*s)->find_by_id(one);
    REQUIRE(c.has_value());
    REQUIRE(c->sign_count == 3);
  }
  // Tamper one ciphertext byte → GCM rejects.
  auto bad = raw;
  bad[bad.size() - 20] ^= 0x01;
  write_all(path, bad);
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  // Wrong version.
  auto v2 = raw;
  v2[4] = 2;
  write_all(path, v2);
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  // Bad magic.
  auto m = raw;
  m[0] = 'X';
  write_all(path, m);
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  // Truncated.
  auto t = raw;
  t.resize(t.size() - 5);
  write_all(path, t);
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  // Restore, but the DEK is gone from the keychain.
  write_all(path, raw);
  REQUIRE(kc.delete_dek("").has_value());
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  // Keychain failure surfaces as an error, not a silent fresh store.
  kc.fail = true;
  REQUIRE_FALSE(open_file_store(path, p, kc).has_value());
  std::filesystem::remove_all(d);
}

TEST_CASE("file store: single instance lock", "[store][file]") {
  crypto::Provider p;
  auto d = tmpdir();
  MemoryKeychain kc;
  auto a = open_file_store(d / "credentials.bin", p, kc);
  REQUIRE(a.has_value());
  auto b = open_file_store(d / "credentials.bin", p, kc);
  REQUIRE_FALSE(b.has_value());
  a->reset();
  auto c = open_file_store(d / "credentials.bin", p, kc);
  REQUIRE(c.has_value());
  std::filesystem::remove_all(d);
}

TEST_CASE("file store: factory reset rotates the DEK and empties the file", "[store][file]") {
  crypto::Provider p;
  auto d = tmpdir();
  const auto path = d / "credentials.bin";
  MemoryKeychain kc;
  auto s = open_file_store(path, p, kc);
  REQUIRE(s.has_value());
  REQUIRE((*s)->put(sw_cred(p, 1)).has_value());
  REQUIRE((*s)->set_pin(PinState{std::array<std::uint8_t, 16>{1}, 8}).has_value());
  std::string id_hex;
  for (auto b : (*s)->install_id()) {
    static constexpr char kH[] = "0123456789abcdef";
    id_hex.push_back(kH[b >> 4]);
    id_hex.push_back(kH[b & 15]);
  }
  auto dek_before = *kc.load_dek(id_hex);
  int destroyed = 0;
  REQUIRE((*s)->factory_reset([&](const Credential&) { ++destroyed; }).has_value());
  REQUIRE(destroyed == 1);
  REQUIRE((*s)->size() == 0);
  REQUIRE_FALSE((*s)->pin().hash.has_value());
  auto dek_after = *kc.load_dek(id_hex);
  REQUIRE(dek_before.has_value());
  REQUIRE(dek_after.has_value());
  REQUIRE(*dek_before != *dek_after);
  // The fresh file is readable with the new DEK.
  s->reset();
  auto again = open_file_store(path, p, kc);
  REQUIRE(again.has_value());
  REQUIRE((*again)->size() == 0);
  std::filesystem::remove_all(d);
}

TEST_CASE("file keychain and fallback", "[store][keychain]") {
  auto d = tmpdir();
  auto fk = make_file_keychain(d / "credentials.bin.dek");
  std::array<std::uint8_t, 32> dek{};
  dek.fill(0x5A);
  REQUIRE_FALSE(fk->load_dek("x")->has_value());
  REQUIRE(fk->store_dek("x", dek).has_value());
  struct stat st{};
  REQUIRE(::stat((d / "credentials.bin.dek").c_str(), &st) == 0);
  REQUIRE((st.st_mode & 0777) == 0600);
  REQUIRE(*fk->load_dek("x") == dek);
  REQUIRE(fk->delete_dek("x").has_value());
  REQUIRE_FALSE(std::filesystem::exists(d / "credentials.bin.dek"));

  // Fallback: failing primary → file.
  auto failing = std::make_unique<MemoryKeychain>();
  failing->fail = true;
  auto fb = make_fallback_keychain(std::move(failing), make_file_keychain(d / "credentials.bin.dek"));
  REQUIRE(fb->store_dek("y", dek).has_value());
  REQUIRE(std::string(fb->name()) == "file");
  REQUIRE(*fb->load_dek("y") == dek);
  // Fallback: working primary keeps its name and is used.
  auto ok = std::make_unique<MemoryKeychain>();
  auto fb2 = make_fallback_keychain(std::move(ok), make_file_keychain(d / "other.dek"));
  REQUIRE(fb2->store_dek("z", dek).has_value());
  REQUIRE(std::string(fb2->name()) == "memory");
  REQUIRE_FALSE(std::filesystem::exists(d / "other.dek"));
  // Null primary → straight to fallback.
  auto fb3 = make_fallback_keychain(nullptr, make_file_keychain(d / "n.dek"));
  REQUIRE(fb3->store_dek("n", dek).has_value());
  REQUIRE(std::filesystem::exists(d / "n.dek"));
  std::filesystem::remove_all(d);
}
