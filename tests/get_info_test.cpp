#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/ctap/get_info.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace swpk;

namespace {

struct Fixture {
  crypto::Provider crypto;
  crypto::SoftwareKeyBackend keys;
  std::unique_ptr<store::CredentialStore> store = store::CredentialStore::open_memory();
  ui::AlwaysDenyPresence presence;
  ctap::Authenticator auth{ctap::AuthenticatorConfig{}, crypto, keys, keys, *store, presence};
};

}  // namespace

TEST_CASE("getInfo snapshot is the PR3 shape", "[getinfo]") {
  Fixture f;
  auto s = f.auth.get_info();
  REQUIRE(s.versions == std::vector<std::string>{"FIDO_2_0"});
  REQUIRE(s.extensions.empty());
  REQUIRE(s.aaguid == kAaguid);
  REQUIRE_FALSE(s.options.client_pin.has_value());
  REQUIRE_FALSE(s.options.pin_uv_auth_token.has_value());
  REQUIRE(s.options.rk);
  REQUIRE(s.options.up);
  REQUIRE_FALSE(s.options.plat);
  REQUIRE(s.pin_protocols.empty());
  REQUIRE(s.max_msg_size == 1200);
  REQUIRE(s.max_creds_in_list == 8);
  REQUIRE(s.max_cred_id_len == 32);
  REQUIRE(s.remaining_discoverable == store::kMaxCredentials);
}

TEST_CASE("getInfo via handle_cbor decodes as a map with sorted integer keys", "[getinfo]") {
  Fixture f;
  ctap::CancelToken tok;
  const std::uint8_t req[] = {ctap::kCmdGetInfo};
  auto r = f.auth.handle_cbor(req, tok);
  REQUIRE(r.has_value());
  cbor::Reader rd(*r);
  auto n = rd.map();
  REQUIRE(n.has_value());
  REQUIRE(*n == 10);
  std::uint64_t last = 0;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = rd.uint();
    REQUIRE(k.has_value());
    REQUIRE(*k > last);
    last = *k;
    REQUIRE(rd.skip().has_value());
  }
  REQUIRE(rd.done());
  REQUIRE(last == 20);
}

TEST_CASE("unknown CTAP command is INVALID_COMMAND", "[getinfo]") {
  Fixture f;
  ctap::CancelToken tok;
  const std::uint8_t req[] = {0x41};
  auto r = f.auth.handle_cbor(req, tok);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == Status::InvalidCommand);
  const std::uint8_t empty[] = {0};
  auto e = f.auth.handle_cbor(std::span<const std::uint8_t>(empty, 0), tok);
  REQUIRE(e.error() == Status::InvalidLength);
}
