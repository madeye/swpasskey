#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <thread>

using namespace swpk;
using namespace swpk::test;

namespace {

struct Assertion {
  std::vector<std::uint8_t> cred_id;
  std::vector<std::uint8_t> auth_data;
  ParsedAuthData ad;
  std::vector<std::uint8_t> sig;
  std::map<std::string, std::vector<std::uint8_t>> user;
  std::optional<std::uint64_t> number;
  bool has_user{false};
};

Assertion parse_assertion(std::span<const std::uint8_t> resp) {
  Assertion a;
  auto m = split_int_map(resp);
  auto d = split_text_map(m[1]);
  a.cred_id = as_bstr(d["id"]);
  a.auth_data = as_bstr(m[2]);
  a.ad = parse_auth_data(a.auth_data);
  a.sig = as_bstr(m[3]);
  if (m.count(4)) {
    a.has_user = true;
    a.user = split_text_map(m[4]);
  }
  if (m.count(5)) {
    cbor::Reader r(m[5]);
    a.number = *r.uint();
  }
  return a;
}

}  // namespace

TEST_CASE("getAssertion discoverable: signs, bumps counter, returns user.id", "[ga]") {
  Rig rig;
  auto id = rig.register_cred();
  auto pub = rig.store->find_by_id(id)->pub;
  GetAssertOpts o;
  o.client_data_hash.fill(0xCD);
  auto r = rig.call(get_assert_request(o));
  REQUIRE(r.has_value());
  auto a = parse_assertion(*r);
  REQUIRE(a.cred_id == id);
  REQUIRE(a.ad.flags == 0x01);
  REQUIRE(a.ad.sign_count == 2);
  REQUIRE(a.auth_data.size() == 37);
  std::vector<std::uint8_t> msg(a.auth_data);
  msg.insert(msg.end(), o.client_data_hash.begin(), o.client_data_hash.end());
  REQUIRE(verify_es256(pub, msg, a.sig));
  REQUIRE(a.has_user);
  REQUIRE(as_bstr(a.user["id"]) == bytes({1, 2, 3, 4}));
  REQUIRE(a.user.count("name") == 0);  // UV=0 → only user.id
  REQUIRE_FALSE(a.number.has_value());
  REQUIRE(rig.store->find_by_id(id)->sign_count == 2);
  REQUIRE(rig.presence.seen.back().kind == ui::PresenceRequest::Kind::GetAssertion);

  // Second assertion continues the counter.
  auto r2 = rig.call(get_assert_request(o));
  REQUIRE(parse_assertion(*r2).ad.sign_count == 3);
}

TEST_CASE("getAssertion pre-flight up=false signs but does not prompt or bump", "[ga]") {
  Rig rig;
  auto id = rig.register_cred();
  auto pub = rig.store->find_by_id(id)->pub;
  const int calls = rig.presence.calls;
  GetAssertOpts o;
  o.up = false;
  auto r = rig.call(get_assert_request(o));
  REQUIRE(r.has_value());
  auto a = parse_assertion(*r);
  REQUIRE(a.ad.flags == 0x00);
  REQUIRE(a.ad.sign_count == 1);
  REQUIRE_FALSE(a.sig.empty());
  std::vector<std::uint8_t> msg(a.auth_data);
  msg.insert(msg.end(), o.client_data_hash.begin(), o.client_data_hash.end());
  REQUIRE(verify_es256(pub, msg, a.sig));
  REQUIRE(rig.presence.calls == calls);
  REQUIRE(rig.store->find_by_id(id)->sign_count == 1);
}

TEST_CASE("getAssertion no credentials / wrong rp / allowList miss", "[ga]") {
  Rig rig;
  GetAssertOpts o;
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::NoCredentials);
  auto id = rig.register_cred();
  o.rp_id = "other.example";
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::NoCredentials);
  o.rp_id = "example.com";
  o.allow = std::vector<std::vector<std::uint8_t>>{bytes({1, 2, 3})};
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::NoCredentials);
  o.allow = std::vector<std::vector<std::uint8_t>>{bytes({1, 2, 3}), id};
  REQUIRE(rig.call(get_assert_request(o)).has_value());
  o.allow = std::vector<std::vector<std::uint8_t>>{};  // empty allowList == discoverable
  REQUIRE(rig.call(get_assert_request(o)).has_value());
}

TEST_CASE("getAssertion UP deny / timeout / cancel / uv option", "[ga]") {
  Rig rig;
  rig.register_cred();
  GetAssertOpts o;
  rig.presence.next = ui::Decision::Deny;
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::OperationDenied);
  rig.presence.next = ui::Decision::Timeout;
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::UserActionTimeout);
  rig.tok.cancel();
  REQUIRE(rig.auth->handle_cbor(get_assert_request(o), rig.tok).error() == Status::KeepaliveCancel);
  o.uv = true;
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::InvalidOption);
  o = {};
  o.pin_auth = bytes({1});
  o.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(o)).error() == Status::PinAuthInvalid);
}

TEST_CASE("getAssertion multiple credentials + getNextAssertion", "[ga]") {
  Rig rig;
  MakeCredOpts a;
  a.user_id = bytes({0xA});
  a.user_name = "a";
  auto id_a = rig.register_cred(a);
  MakeCredOpts b;
  b.user_id = bytes({0xB});
  b.user_name = "b";
  auto id_b = rig.register_cred(b);
  // Make `a` the most recently used.
  (void)rig.store->update_count_and_used(id_a, 5, 4102444800ULL);

  GetAssertOpts o;
  auto r1 = rig.call(get_assert_request(o));
  REQUIRE(r1.has_value());
  auto p1 = parse_assertion(*r1);
  REQUIRE(p1.number == 2);
  REQUIRE(p1.cred_id == id_a);
  REQUIRE(as_bstr(p1.user["id"]) == bytes({0xA}));
  REQUIRE(p1.ad.sign_count == 6);

  const std::uint8_t next[] = {ctap::kCmdGetNextAssertion};
  auto r2 = rig.call(std::vector<std::uint8_t>(next, next + 1));
  REQUIRE(r2.has_value());
  auto p2 = parse_assertion(*r2);
  REQUIRE(p2.cred_id == id_b);
  REQUIRE_FALSE(p2.number.has_value());
  REQUIRE(p2.ad.flags == 0x01);
  REQUIRE(rig.store->find_by_id(id_b)->sign_count == 2);
  REQUIRE(rig.presence.calls == 3);  // no extra UP for getNextAssertion

  // State consumed → NOT_ALLOWED.
  REQUIRE(rig.call(std::vector<std::uint8_t>(next, next + 1)).error() == Status::NotAllowed);
  // getNextAssertion with no prior getAssertion.
  Rig fresh;
  REQUIRE(fresh.call(std::vector<std::uint8_t>(next, next + 1)).error() == Status::NotAllowed);
}

TEST_CASE("getAssertion mixed backends: software row + fake-TPM row", "[ga]") {
  Rig rig(true);  // primary = fake TPM
  auto hw_id = rig.register_cred();
  // Legacy software row inserted directly.
  auto k = rig.software.generate();
  REQUIRE(k.has_value());
  store::Credential sw;
  sw.rp_id = "example.com";
  sw.rp_id_hash = rig.crypto.sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>("example.com"), 11));
  sw.user_id = bytes({7});
  sw.cred_id.fill(0x77);
  sw.backend = crypto::BackendKind::Software;
  auto sc = crypto::SoftwareKeyBackend::export_scalar_for_store(**k);
  sw.priv.assign(sc->begin(), sc->end());
  sw.pub = (*k)->pub();
  sw.created_unix = 1;
  REQUIRE(rig.store->put(sw).has_value());

  GetAssertOpts o;
  o.allow = std::vector<std::vector<std::uint8_t>>{std::vector<std::uint8_t>(sw.cred_id.begin(), sw.cred_id.end())};
  auto r = rig.call(get_assert_request(o));
  REQUIRE(r.has_value());
  auto p = parse_assertion(*r);
  std::vector<std::uint8_t> msg(p.auth_data);
  msg.insert(msg.end(), o.client_data_hash.begin(), o.client_data_hash.end());
  REQUIRE(verify_es256(sw.pub, msg, p.sig));
  REQUIRE(static_cast<FakeHwBackend*>(rig.hw.get())->loads == 0);

  o.allow = std::vector<std::vector<std::uint8_t>>{hw_id};
  auto r2 = rig.call(get_assert_request(o));
  REQUIRE(r2.has_value());
  REQUIRE(static_cast<FakeHwBackend*>(rig.hw.get())->loads == 1);
}

TEST_CASE("HW row fails closed when the probed backend differs", "[ga]") {
  Rig hw_rig(true);
  auto hw_id = hw_rig.register_cred();
  auto row = *hw_rig.store->find_by_id(hw_id);
  Rig sw_rig;  // software-only daemon sees the TPM row
  REQUIRE(sw_rig.store->put(row).has_value());
  GetAssertOpts o;
  REQUIRE(sw_rig.call(get_assert_request(o)).error() == Status::InvalidCredential);
}

TEST_CASE("reset requires UP and wipes everything", "[reset]") {
  Rig rig(true);
  rig.register_cred();
  rig.register_cred();
  const std::uint8_t reset[] = {ctap::kCmdReset};
  rig.presence.next = ui::Decision::Deny;
  REQUIRE(rig.call(std::vector<std::uint8_t>(reset, reset + 1)).error() == Status::OperationDenied);
  REQUIRE(rig.store->size() == 2);
  rig.presence.next = ui::Decision::Allow;
  auto r = rig.call(std::vector<std::uint8_t>(reset, reset + 1));
  REQUIRE(r.has_value());
  REQUIRE(r->empty());
  REQUIRE(rig.store->size() == 0);
  REQUIRE(static_cast<FakeHwBackend*>(rig.hw.get())->destroys == 2);
  REQUIRE(rig.presence.seen.back().kind == ui::PresenceRequest::Kind::Reset);
}
