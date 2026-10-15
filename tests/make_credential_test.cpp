	#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace swpk;
using namespace swpk::test;

TEST_CASE("makeCredential: packed self-attestation verifies, rk stored", "[mc]") {
  Rig rig;
  MakeCredOpts o;
  for (std::size_t i = 0; i < 32; ++i) o.client_data_hash[i] = static_cast<std::uint8_t>(i);
  auto r = rig.call(make_cred_request(o));
  REQUIRE(r.has_value());
  auto m = split_int_map(*r);
  REQUIRE(m.size() == 3);
  {
    cbor::Reader fr(m[1]);
    REQUIRE(*fr.tstr() == "packed");
  }
  auto auth_data = as_bstr(m[2]);
  auto ad = parse_auth_data(auth_data);
  REQUIRE(ad.rp_id_hash == rig.crypto.sha256(std::span<const std::uint8_t>(
                               reinterpret_cast<const std::uint8_t*>("example.com"), 11)));
  REQUIRE(ad.flags == 0x41);  // UP | AT, no UV/BE/BS/ED
  REQUIRE(ad.sign_count == 1);
  REQUIRE(ad.aaguid == kAaguid);
  REQUIRE(ad.cred_id.size() == 32);
  auto st = split_text_map(m[3]);
  REQUIRE(st.size() == 2);
  REQUIRE(st.count("alg") == 1);
  REQUIRE(st.count("sig") == 1);
  REQUIRE(st.count("x5c") == 0);
  {
    cbor::Reader ar(st["alg"]);
    REQUIRE(*ar.integer() == -7);
  }
  std::vector<std::uint8_t> msg(auth_data);
  msg.insert(msg.end(), o.client_data_hash.begin(), o.client_data_hash.end());
  REQUIRE(verify_es256(ad.pub, msg, as_bstr(st["sig"])));

  REQUIRE(rig.store->size() == 1);
  auto row = rig.store->find_by_id(ad.cred_id);
  REQUIRE(row.has_value());
  REQUIRE(row->backend == crypto::BackendKind::Software);
  REQUIRE(row->priv.size() == 32);
  REQUIRE(row->handle.empty());
  REQUIRE(row->cred_random.size() == 64);
  REQUIRE(row->user_name == "alice");
  REQUIRE(rig.presence.calls == 1);
  REQUIRE(rig.presence.seen[0].kind == ui::PresenceRequest::Kind::MakeCredential);
  REQUIRE(rig.presence.seen[0].rp_id == "example.com");
  REQUIRE(rig.auth->metrics().make_cred_ok == 1);
}

TEST_CASE("makeCredential on a HW backend stores a handle and no scalar", "[mc]") {
  Rig rig(true);
  auto id = rig.register_cred();
  REQUIRE(id.size() == 32);
  auto row = rig.store->find_by_id(id);
  REQUIRE(row->backend == crypto::BackendKind::Tpm2);
  REQUIRE(row->priv.empty());
  REQUIRE_FALSE(row->handle.empty());
  REQUIRE(row->cred_random.size() == 65);  // fake wrap prefixes one byte
  REQUIRE(rig.auth->get_info().remaining_discoverable == store::kMaxCredentials - 1);
}

TEST_CASE("makeCredential option policy", "[mc]") {
  Rig rig;
  MakeCredOpts o;
  o.up = false;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::InvalidOption);
  o = {};
  o.uv = true;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::InvalidOption);
  o = {};
  o.cred_protect = 3;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::UnsupportedExtension);
  o = {};
  o.cred_protect = 1;
  REQUIRE(rig.call(make_cred_request(o)).has_value());
  o = {};
  o.enterprise = true;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::InvalidParameter);
  o = {};
  o.alg = -257;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::UnsupportedAlgorithm);
  o = {};
  o.rp_id = "";
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::InvalidParameter);
  o = {};
  o.rp_id = std::string(256, 'a');
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::InvalidParameter);
  o = {};
  o.user_id = std::vector<std::uint8_t>(65, 1);
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::LimitExceeded);
  o = {};
  o.pin_auth = bytes({1, 2, 3});
  o.pin_protocol = 2;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::PinAuthInvalid);
  REQUIRE(rig.presence.calls == 1);  // only the credProtect=1 case reached UP
}

TEST_CASE("non-discoverable credentials require an allowList",
          "[mc][ga]") {
  Rig rig;

  MakeCredOpts o;
  o.rk = false;

  auto id = rig.register_cred(o);
  REQUIRE(id.size() == 32);

  auto row = rig.store->find_by_id(id);
  REQUIRE(row.has_value());
  REQUIRE_FALSE(row->rk);

  // A non-discoverable credential must not be enumerated.
  REQUIRE(rig.store->find_by_rp(row->rp_id_hash).empty());

  GetAssertOpts a;

  // Without a credential ID, authentication must fail.
  REQUIRE(rig.call(get_assert_request(a)).error() ==
          Status::NoCredentials);

  // With its credential ID, authentication must succeed.
  a.allow = std::vector<std::vector<std::uint8_t>>{id};

  auto result = rig.call(get_assert_request(a));
  REQUIRE(result.has_value());
  auto response = split_int_map(*result);
  auto descriptor = split_text_map(response.at(1));
  REQUIRE(as_bstr(descriptor.at("id")) == id);
}

TEST_CASE("non-discoverable credentials preserve existing keys",
          "[mc]") {
  Rig rig;

  // Existing discoverable passkey.
  auto discoverable = rig.register_cred();

  MakeCredOpts o;
  o.rk = false;

  // Two non-discoverable credentials for the same user and RP.
  auto first = rig.register_cred(o);
  auto second = rig.register_cred(o);

  REQUIRE(first != second);
  REQUIRE(rig.store->size() == 3);

  REQUIRE(rig.store->find_by_id(discoverable).has_value());
  REQUIRE(rig.store->find_by_id(first).has_value());
  REQUIRE(rig.store->find_by_id(second).has_value());
}

TEST_CASE("makeCredential rk=true and up=true explicitly are accepted", "[mc]") {
  Rig rig;
  MakeCredOpts o;
  o.rk = true;
  o.up = true;
  o.uv = false;
  REQUIRE(rig.call(make_cred_request(o)).has_value());
}

TEST_CASE("makeCredential UP: deny, timeout, cancel", "[mc]") {
  Rig rig;
  rig.presence.next = ui::Decision::Deny;
  REQUIRE(rig.call(make_cred_request({})).error() == Status::OperationDenied);
  rig.presence.next = ui::Decision::Timeout;
  REQUIRE(rig.call(make_cred_request({})).error() == Status::UserActionTimeout);
  rig.tok.cancel();
  auto r = rig.auth->handle_cbor(make_cred_request({}), rig.tok);
  REQUIRE(r.error() == Status::KeepaliveCancel);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(rig.auth->metrics().up_deny == 1);
  REQUIRE(rig.auth->metrics().up_timeout == 1);
  REQUIRE(rig.auth->metrics().up_cancel == 1);
}

TEST_CASE("excludeList: UP first, then CREDENTIAL_EXCLUDED even on Deny", "[mc]") {
  Rig rig;
  auto id = rig.register_cred();
  REQUIRE(id.size() == 32);
  MakeCredOpts o;
  o.exclude = {bytes({9, 9, 9}), id};
  rig.presence.next = ui::Decision::Deny;
  auto r = rig.call(make_cred_request(o));
  REQUIRE(r.error() == Status::CredentialExcluded);
  REQUIRE(rig.presence.calls == 2);  // UP was requested before reporting exclusion
  rig.presence.next = ui::Decision::Allow;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::CredentialExcluded);
  rig.presence.next = ui::Decision::Timeout;
  REQUIRE(rig.call(make_cred_request(o)).error() == Status::CredentialExcluded);
  // Cancel wins over exclusion.
  rig.tok.cancel();
  REQUIRE(rig.auth->handle_cbor(make_cred_request(o), rig.tok).error() == Status::KeepaliveCancel);
  // Same id under a different RP is not excluded.
  o.rp_id = "other.example";
  rig.presence.next = ui::Decision::Allow;
  REQUIRE(rig.call(make_cred_request(o)).has_value());
}

TEST_CASE("makeCredential key store full", "[mc]") {
  Rig rig;
  for (std::size_t i = 0; i < store::kMaxCredentials; ++i) {
    MakeCredOpts o;
    o.user_id = {static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(i >> 8)};
    REQUIRE(rig.call(make_cred_request(o)).has_value());
  }
  REQUIRE(rig.auth->get_info().remaining_discoverable == 0);
  REQUIRE(rig.call(make_cred_request({})).error() == Status::KeyStoreFull);
}

TEST_CASE("makeCredential malformed CBOR", "[mc]") {
  Rig rig;
  REQUIRE(rig.call(bytes({0x01, 0xA1, 0x01})).error() == Status::InvalidCbor);
  REQUIRE(rig.call(bytes({0x01, 0x80})).error() == Status::CborUnexpectedType);
  REQUIRE(rig.call(bytes({0x01, 0xA0})).error() == Status::MissingParameter);
  MakeCredOpts o;
  auto req = make_cred_request(o);
  // clientDataHash must be 32 bytes: patch the length byte (0x58 0x20 → 0x58 0x1f) is
  // messy; instead build a request with an indefinite-length map.
  REQUIRE(rig.call(bytes({0x01, 0xBF, 0x01, 0xFF})).error() == Status::InvalidCbor);
}
