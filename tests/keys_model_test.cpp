#include "swpasskey/ui/keys_model.hpp"

#include "swpasskey/store/credential.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace swpk;
using namespace swpk::ui;

namespace {

store::Credential cred(const std::string& rp, const std::string& user, std::uint64_t created,
                       crypto::BackendKind backend, std::uint8_t id_fill, bool rk = true) {
  store::Credential c;
  c.rp_id = rp;
  c.rp_name = rp + " name";
  c.rp_id_hash.fill(id_fill);
  c.user_id = {1, 2, 3, id_fill};
  c.user_name = user;
  c.user_display = user + " D";
  c.cred_id.fill(id_fill);
  c.backend = backend;
  if (backend != crypto::BackendKind::Software) {
    c.handle = {9, 9, 9};
  } else {
    c.priv.assign(32, 7);
  }
  c.pub.x.fill(id_fill);
  c.pub.y.fill(id_fill);
  c.sign_count = 5;
  c.created_unix = created;
  c.last_used_unix = created + 60;
  c.cred_random.assign(64, 1);
  c.rk = rk;
  return c;
}

}  // namespace

TEST_CASE("keys model: rows are sorted by rp, user, creation and labelled", "[ui][keys]") {
  auto store = store::CredentialStore::open_memory();
  REQUIRE(store);
  REQUIRE(store->put(cred("zeta.example", "b", 200, crypto::BackendKind::Software, 0x01)).has_value());
  REQUIRE(store->put(cred("alpha.example", "z", 300, crypto::BackendKind::SecureEnclave, 0x02)).has_value());
  REQUIRE(store->put(cred("alpha.example", "a", 400, crypto::BackendKind::Tpm2, 0x03)).has_value());
  REQUIRE(store->put(cred("alpha.example", "a", 100, crypto::BackendKind::Software, 0x04, false)).has_value());

  const auto rows = key_rows(*store);
  REQUIRE(rows.size() == 4);
  REQUIRE(rows[0].rp_id == "alpha.example");
  REQUIRE(rows[0].user_name == "a");
  REQUIRE(rows[0].created_unix == 100);
  REQUIRE(rows[0].u2f);
  REQUIRE(rows[0].backend == "Software");
  REQUIRE(rows[1].user_name == "a");
  REQUIRE(rows[1].created_unix == 400);
  REQUIRE(rows[1].backend == "TPM 2.0");
  REQUIRE_FALSE(rows[1].u2f);
  REQUIRE(rows[2].user_name == "z");
  REQUIRE(rows[2].backend == "Secure Enclave");
  REQUIRE(rows[3].rp_id == "zeta.example");
  std::string expect;
  for (int i = 0; i < 32; ++i) expect += "01";
  REQUIRE(rows[3].cred_id_hex == expect);
  REQUIRE(rows[3].sign_count == 5);
  REQUIRE(rows[3].last_used_unix == 260);
}

TEST_CASE("keys model: formatting helpers", "[ui][keys]") {
  REQUIRE(format_unix_time(0).empty());
  const auto s = format_unix_time(1'700'000'000);  // 2023-11-14 22:13:20 UTC
  REQUIRE(s.size() == 16);
  REQUIRE(s.substr(0, 4) == "2023");
  REQUIRE(s[4] == '-');
  REQUIRE(s[10] == ' ');
  REQUIRE(s[13] == ':');
  REQUIRE(hex_string(std::array<std::uint8_t, 3>{0x00, 0xab, 0xff}) == "00abff");
  REQUIRE(keys_summary(0, "Secure Enclave") == "0 keys \xC2\xB7 Secure Enclave");
  REQUIRE(keys_summary(1, "") == "1 key");
  REQUIRE(keys_summary(2, "Software") == "2 keys \xC2\xB7 Software");
  REQUIRE(std::string(backend_label(crypto::BackendKind::SecureEnclave)) == "Secure Enclave");
}
