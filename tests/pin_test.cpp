#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/crypto.h>

#include <thread>

using namespace swpk;
using namespace swpk::test;

namespace {

// Platform side of PIN protocol 2, built on the same Provider primitives.
struct PinClient {
  Rig& rig;
  std::unique_ptr<crypto::Provider::SoftwareEcdhKey> key;
  std::array<std::uint8_t, 32> hmac_key{};
  std::array<std::uint8_t, 32> aes_key{};

  explicit PinClient(Rig& r) : rig(r) { handshake(); }

  static std::vector<std::uint8_t> cp(const std::vector<Entry>& entries) {
    Writer w;
    w.write_map(entries);
    auto b = w.finish();
    b.insert(b.begin(), ctap::kCmdClientPin);
    return b;
  }

  static std::vector<std::uint8_t> cose(const crypto::P256PublicKey& pub) {
    std::vector<Entry> m;
    m.emplace_back(Writer::encode_int(1), Writer::encode_int(2));
    m.emplace_back(Writer::encode_int(3), Writer::encode_int(-25));
    m.emplace_back(Writer::encode_int(-1), Writer::encode_int(1));
    m.emplace_back(Writer::encode_int(-2), Writer::encode_bstr(pub.x));
    m.emplace_back(Writer::encode_int(-3), Writer::encode_bstr(pub.y));
    Writer w;
    w.write_map(std::move(m));
    return w.finish();
  }

  void handshake() {
    auto r = rig.call(cp({{Writer::encode_uint(1), Writer::encode_uint(2)}, {Writer::encode_uint(2), Writer::encode_uint(2)}}));
    REQUIRE(r.has_value());
    auto m = split_int_map(*r);
    cbor::Reader rd(m[1]);
    auto n = rd.map();
    REQUIRE(n.has_value());
    crypto::P256PublicKey auth_pub;
    for (std::size_t i = 0; i < *n; ++i) {
      auto k = rd.integer();
      REQUIRE(k.has_value());
      if (*k == -2 || *k == -3) {
        auto b = rd.bstr();
        REQUIRE(b->size() == 32);
        std::memcpy(*k == -2 ? auth_pub.x.data() : auth_pub.y.data(), b->data(), 32);
      } else if (*k == 3) {
        REQUIRE(*rd.integer() == -25);
      } else {
        REQUIRE(rd.skip().has_value());
      }
    }
    key = *rig.crypto.generate_p256_ephemeral();
    auto z = *key->shared_secret_x(auth_pub);
    const std::uint8_t salt[32] = {};
    const char* h = "CTAP2 HMAC key";
    const char* a = "CTAP2 AES key";
    hmac_key = *rig.crypto.hkdf_sha256(z, salt, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(h), 14));
    aes_key = *rig.crypto.hkdf_sha256(z, salt, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(a), 13));
  }

  std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> pt) {
    std::array<std::uint8_t, 16> iv{};
    REQUIRE(rig.crypto.random(iv).has_value());
    auto ct = *rig.crypto.aes256cbc_encrypt(aes_key, iv, pt);
    std::vector<std::uint8_t> out(iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
  }
  std::vector<std::uint8_t> decrypt(std::span<const std::uint8_t> ct) {
    std::array<std::uint8_t, 16> iv{};
    std::memcpy(iv.data(), ct.data(), 16);
    return *rig.crypto.aes256cbc_decrypt(aes_key, iv, ct.subspan(16));
  }
  std::vector<std::uint8_t> auth(std::span<const std::uint8_t> key_, std::span<const std::uint8_t> msg) {
    auto m = *rig.crypto.hmac_sha256(key_, msg);
    return std::vector<std::uint8_t>(m.begin(), m.end());
  }
  std::array<std::uint8_t, 16> pin_hash(const std::string& pin) {
    auto d = rig.crypto.sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
    std::array<std::uint8_t, 16> h{};
    std::memcpy(h.data(), d.data(), 16);
    return h;
  }
  std::vector<std::uint8_t> padded(const std::string& pin) {
    std::vector<std::uint8_t> p(64, 0);
    std::memcpy(p.data(), pin.data(), pin.size());
    return p;
  }

  Result<std::vector<std::uint8_t>> set_pin(const std::string& pin) {
    auto enc = encrypt(padded(pin));
    return rig.call(cp({{Writer::encode_uint(1), Writer::encode_uint(2)},
                        {Writer::encode_uint(2), Writer::encode_uint(3)},
                        {Writer::encode_uint(3), cose(key->pub())},
                        {Writer::encode_uint(4), Writer::encode_bstr(auth(hmac_key, enc))},
                        {Writer::encode_uint(5), Writer::encode_bstr(enc)}}));
  }

  Result<std::vector<std::uint8_t>> change_pin(const std::string& old_pin, const std::string& new_pin) {
    auto new_enc = encrypt(padded(new_pin));
    auto hash_enc = encrypt(pin_hash(old_pin));
    std::vector<std::uint8_t> msg(new_enc);
    msg.insert(msg.end(), hash_enc.begin(), hash_enc.end());
    return rig.call(cp({{Writer::encode_uint(1), Writer::encode_uint(2)},
                        {Writer::encode_uint(2), Writer::encode_uint(4)},
                        {Writer::encode_uint(3), cose(key->pub())},
                        {Writer::encode_uint(4), Writer::encode_bstr(auth(hmac_key, msg))},
                        {Writer::encode_uint(5), Writer::encode_bstr(new_enc)},
                        {Writer::encode_uint(6), Writer::encode_bstr(hash_enc)}}));
  }

  // Returns the decrypted 32-byte token.
  Result<std::vector<std::uint8_t>> token(const std::string& pin, std::optional<std::uint64_t> perms,
                                          std::optional<std::string> rp_id) {
    auto hash_enc = encrypt(pin_hash(pin));
    std::vector<Entry> e = {{Writer::encode_uint(1), Writer::encode_uint(2)},
                            {Writer::encode_uint(2), Writer::encode_uint(perms ? 9 : 5)},
                            {Writer::encode_uint(3), cose(key->pub())},
                            {Writer::encode_uint(6), Writer::encode_bstr(hash_enc)}};
    if (perms) e.emplace_back(Writer::encode_uint(9), Writer::encode_uint(*perms));
    if (rp_id) e.emplace_back(Writer::encode_uint(10), Writer::encode_tstr(*rp_id));
    auto r = rig.call(cp(e));
    if (!r) return std::unexpected(r.error());
    auto m = split_int_map(*r);
    auto enc = as_bstr(m[2]);
    REQUIRE(enc.size() == 48);
    return decrypt(enc);
  }

  std::uint64_t retries() {
    auto r = rig.call(cp({{Writer::encode_uint(2), Writer::encode_uint(1)}}));
    REQUIRE(r.has_value());
    auto m = split_int_map(*r);
    cbor::Reader rd(m[3]);
    return *rd.uint();
  }

  std::vector<std::uint8_t> param(const std::vector<std::uint8_t>& tok, const std::array<std::uint8_t, 32>& cdh) {
    return auth(tok, cdh);
  }
};

}  // namespace

TEST_CASE("clientPIN: retries, key agreement, setPIN, policy", "[pin]") {
  Rig rig;
  PinClient c(rig);
  REQUIRE(c.retries() == 8);
  REQUIRE(rig.auth->get_info().options.client_pin == false);
  REQUIRE(c.set_pin("123").error() == Status::PinPolicyViolation);
  REQUIRE(c.set_pin(std::string(64, 'a')).error() == Status::PinPolicyViolation);
  REQUIRE(c.set_pin("1234").has_value());
  REQUIRE(rig.auth->get_info().options.client_pin == true);
  REQUIRE(rig.store->pin().hash.has_value());
  REQUIRE(*rig.store->pin().hash == c.pin_hash("1234"));
  REQUIRE(c.set_pin("5678").error() == Status::PinAuthInvalid);  // already set
  // Bad pinUvAuthParam on setPIN in a fresh rig.
  Rig rig2;
  PinClient c2(rig2);
  auto enc = c2.encrypt(c2.padded("1234"));
  auto bad = c2.auth(c2.hmac_key, enc);
  bad[0] ^= 1;
  REQUIRE(rig2.call(PinClient::cp({{Writer::encode_uint(1), Writer::encode_uint(2)},
                                   {Writer::encode_uint(2), Writer::encode_uint(3)},
                                   {Writer::encode_uint(3), PinClient::cose(c2.key->pub())},
                                   {Writer::encode_uint(4), Writer::encode_bstr(bad)},
                                   {Writer::encode_uint(5), Writer::encode_bstr(enc)}})).error() == Status::PinAuthInvalid);
  // Protocol 1 / missing protocol / unsupported subcommand.
  REQUIRE(rig2.call(PinClient::cp({{Writer::encode_uint(1), Writer::encode_uint(1)}, {Writer::encode_uint(2), Writer::encode_uint(2)}})).error() == Status::InvalidParameter);
  REQUIRE(rig2.call(PinClient::cp({{Writer::encode_uint(2), Writer::encode_uint(2)}})).error() == Status::MissingParameter);
  REQUIRE(rig2.call(PinClient::cp({{Writer::encode_uint(1), Writer::encode_uint(2)}, {Writer::encode_uint(2), Writer::encode_uint(6)}})).error() == Status::InvalidSubcommand);
}

TEST_CASE("clientPIN: tokens, retries, lockout", "[pin]") {
  Rig rig;
  PinClient c(rig);
  REQUIRE(c.token("1234", std::nullopt, std::nullopt).error() == Status::PinNotSet);
  REQUIRE(c.set_pin("1234").has_value());
  REQUIRE(c.token("9999", std::nullopt, std::nullopt).error() == Status::PinInvalid);
  REQUIRE(c.retries() == 7);
  c.handshake();  // authenticator regenerated its key after the failure
  auto t = c.token("1234", std::nullopt, std::nullopt);
  REQUIRE(t.has_value());
  REQUIRE(t->size() == 32);
  REQUIRE(c.retries() == 8);
  REQUIRE(rig.auth->metrics().pin_fail == 1);
  // Lockout after 8 consecutive failures (delays shrunk by the Rig config).
  for (int i = 0; i < 8; ++i) {
    c.handshake();
    auto e = c.token("0000", std::nullopt, std::nullopt).error();
    REQUIRE((e == Status::PinInvalid || e == Status::PinBlocked));
  }
  REQUIRE(c.retries() == 0);
  c.handshake();
  REQUIRE(c.token("1234", std::nullopt, std::nullopt).error() == Status::PinBlocked);
  REQUIRE(rig.auth->metrics().pin_block >= 1);
  // Reset clears the PIN and retries.
  const std::uint8_t reset[] = {ctap::kCmdReset};
  REQUIRE(rig.call(std::vector<std::uint8_t>(reset, reset + 1)).has_value());
  REQUIRE(rig.auth->get_info().options.client_pin == false);
  c.handshake();
  REQUIRE(c.retries() == 8);
  REQUIRE(c.set_pin("abcd").has_value());
}

TEST_CASE("PIN token drives make/get: not one-shot, permissions, rpId binding", "[pin]") {
  Rig rig;
  PinClient c(rig);
  REQUIRE(c.set_pin("1234").has_value());
  // makeCredential without a token now fails; getAssertion without is fine (UV=0).
  MakeCredOpts mo;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::PuattRequired);
  // Permissions parsing on 0x09.
  REQUIRE(c.token("1234", 0x01, std::nullopt).error() == Status::UnauthorizedPermission);  // mc without rpId
  REQUIRE(c.token("1234", 0x04, std::string("example.com")).error() == Status::UnauthorizedPermission);  // cm
  REQUIRE(c.token("1234", 0, std::string("example.com")).error() == Status::InvalidParameter);
  auto tok = c.token("1234", 0x03, std::string("example.com"));
  REQUIRE(tok.has_value());
  // Pre-flight getAssertion then makeCredential with the SAME token (Chrome, K23).
  GetAssertOpts ga;
  ga.up = false;
  ga.pin_auth = c.param(*tok, ga.client_data_hash);
  ga.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(ga)).error() == Status::NoCredentials);
  mo.pin_auth = c.param(*tok, mo.client_data_hash);
  mo.pin_protocol = 2;
  auto r = rig.call(make_cred_request(mo));
  REQUIRE(r.has_value());
  auto m = split_int_map(*r);
  auto ad = parse_auth_data(as_bstr(m[2]));
  REQUIRE((ad.flags & 0x04) != 0);  // UV
  const auto cred_id = ad.cred_id;
  // Wrong protocol / bad HMAC / missing protocol.
  mo.pin_protocol = 1;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::InvalidParameter);
  mo.pin_protocol = std::nullopt;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::MissingParameter);
  mo.pin_protocol = 2;
  mo.pin_auth = bytes({1, 2, 3});
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::PinAuthInvalid);
  // getAssertion with the token → UV=1 and the full user entity; without → UV=0, id only.
  GetAssertOpts g2;
  g2.allow = std::vector<std::vector<std::uint8_t>>{cred_id};
  g2.pin_auth = c.param(*tok, g2.client_data_hash);
  g2.pin_protocol = 2;
  auto a = rig.call(get_assert_request(g2));
  REQUIRE(a.has_value());
  auto am = split_int_map(*a);
  REQUIRE((parse_auth_data(as_bstr(am[2])).flags & 0x05) == 0x05);
  auto user = split_text_map(am[4]);
  REQUIRE(user.count("name") == 1);
  REQUIRE(user.count("displayName") == 1);
  GetAssertOpts g3;
  g3.allow = g2.allow;
  auto a3 = rig.call(get_assert_request(g3));
  REQUIRE(a3.has_value());
  REQUIRE((parse_auth_data(as_bstr(split_int_map(*a3)[2])).flags & 0x04) == 0);
  // Token bound to example.com cannot be used for another rpId.
  GetAssertOpts g4;
  g4.rp_id = "other.example";
  g4.pin_auth = c.param(*tok, g4.client_data_hash);
  g4.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(g4)).error() == Status::PinAuthInvalid);
  // ga-only token cannot makeCredential.
  auto ga_tok = c.token("1234", 0x02, std::nullopt);
  REQUIRE(ga_tok.has_value());
  mo.pin_auth = c.param(*ga_tok, mo.client_data_hash);
  mo.pin_protocol = 2;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::UnauthorizedPermission);
  // getPinToken (0x05): mc|ga, binds on first use.
  auto legacy = c.token("1234", std::nullopt, std::nullopt);
  REQUIRE(legacy.has_value());
  GetAssertOpts g5;
  g5.rp_id = "first.example";
  g5.pin_auth = c.param(*legacy, g5.client_data_hash);
  g5.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(g5)).error() == Status::NoCredentials);  // verified, then no creds
  GetAssertOpts g6;
  g6.rp_id = "second.example";
  g6.pin_auth = c.param(*legacy, g6.client_data_hash);
  g6.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(g6)).error() == Status::PinAuthInvalid);  // bound to first.example
  // changePIN invalidates the outstanding token.
  auto fresh = c.token("1234", 0x03, std::string("example.com"));
  REQUIRE(fresh.has_value());
  REQUIRE(c.change_pin("1234", "4321").has_value());
  GetAssertOpts g7;
  g7.allow = g2.allow;
  g7.pin_auth = c.param(*fresh, g7.client_data_hash);
  g7.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(g7)).error() == Status::PinAuthInvalid);
  REQUIRE(c.change_pin("1234", "9999").error() == Status::PinInvalid);
  c.handshake();
  REQUIRE(c.token("4321", 0x02, std::nullopt).has_value());
}

TEST_CASE("PIN token idle timeout and zero-length pinUvAuthParam", "[pin]") {
  Rig rig;
  PinClient c(rig);
  // Zero-length param: UP then PIN_NOT_SET; after setPIN → PIN_INVALID.
  MakeCredOpts mo;
  mo.pin_auth = std::vector<std::uint8_t>{};
  mo.pin_protocol = 2;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::PinNotSet);
  REQUIRE(rig.presence.calls == 1);
  rig.presence.next = ui::Decision::Deny;
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::OperationDenied);
  rig.presence.next = ui::Decision::Allow;
  REQUIRE(c.set_pin("1234").has_value());
  REQUIRE(rig.call(make_cred_request(mo)).error() == Status::PinInvalid);
  GetAssertOpts ga;
  ga.pin_auth = std::vector<std::uint8_t>{};
  ga.pin_protocol = 2;
  REQUIRE(rig.call(get_assert_request(ga)).error() == Status::PinInvalid);
  // Idle timeout (300 ms in the Rig).
  auto tok = c.token("1234", 0x03, std::string("example.com"));
  REQUIRE(tok.has_value());
  std::this_thread::sleep_for(std::chrono::milliseconds(400));
  MakeCredOpts m2;
  m2.pin_auth = c.param(*tok, m2.client_data_hash);
  m2.pin_protocol = 2;
  REQUIRE(rig.call(make_cred_request(m2)).error() == Status::PinAuthInvalid);
}
