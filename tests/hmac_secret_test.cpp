#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace swpk;
using namespace swpk::test;

namespace {

// Platform side of the hmac-secret getAssertion extension (protocol 2).
struct HmacClient {
  Rig& rig;
  std::unique_ptr<crypto::Provider::SoftwareEcdhKey> key;
  std::array<std::uint8_t, 32> hmac_key{}, aes_key{};

  explicit HmacClient(Rig& r) : rig(r) { handshake(); }

  void handshake() {
    std::vector<Entry> e = {{Writer::encode_uint(1), Writer::encode_uint(2)}, {Writer::encode_uint(2), Writer::encode_uint(2)}};
    Writer w;
    w.write_map(e);
    auto b = w.finish();
    b.insert(b.begin(), ctap::kCmdClientPin);
    auto r = rig.call(b);
    REQUIRE(r.has_value());
    auto m = split_int_map(*r);
    cbor::Reader rd(m[1]);
    auto n = rd.map();
    crypto::P256PublicKey auth_pub;
    for (std::size_t i = 0; i < *n; ++i) {
      auto k = *rd.integer();
      if (k == -2 || k == -3) {
        auto bs = *rd.bstr();
        std::memcpy(k == -2 ? auth_pub.x.data() : auth_pub.y.data(), bs.data(), 32);
      } else {
        REQUIRE(rd.skip().has_value());
      }
    }
    key = *rig.crypto.generate_p256_ephemeral();
    auto z = *key->shared_secret_x(auth_pub);
    const std::uint8_t salt[32] = {};
    hmac_key = *rig.crypto.hkdf_sha256(z, salt, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("CTAP2 HMAC key"), 14));
    aes_key = *rig.crypto.hkdf_sha256(z, salt, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("CTAP2 AES key"), 13));
  }

  std::vector<std::uint8_t> cose() const {
    std::vector<Entry> m;
    m.emplace_back(Writer::encode_int(1), Writer::encode_int(2));
    m.emplace_back(Writer::encode_int(3), Writer::encode_int(-25));
    m.emplace_back(Writer::encode_int(-1), Writer::encode_int(1));
    m.emplace_back(Writer::encode_int(-2), Writer::encode_bstr(key->pub().x));
    m.emplace_back(Writer::encode_int(-3), Writer::encode_bstr(key->pub().y));
    Writer w;
    w.write_map(std::move(m));
    return w.finish();
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

  // Encoded {1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: 2}
  std::vector<std::uint8_t> ext(std::span<const std::uint8_t> salts, bool corrupt_auth = false, int protocol = 2) {
    auto salt_enc = encrypt(salts);
    auto mac = *rig.crypto.hmac_sha256(hmac_key, salt_enc);
    if (corrupt_auth) mac[0] ^= 1;
    std::vector<Entry> m;
    m.emplace_back(Writer::encode_uint(1), cose());
    m.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(salt_enc));
    m.emplace_back(Writer::encode_uint(3), Writer::encode_bstr(mac));
    m.emplace_back(Writer::encode_uint(4), Writer::encode_uint(static_cast<std::uint64_t>(protocol)));
    Writer w;
    w.write_map(std::move(m));
    return w.finish();
  }

  // Returns the decrypted outputs (32 or 64 bytes) from an assertion response.
  std::vector<std::uint8_t> outputs(std::span<const std::uint8_t> resp) {
    auto m = split_int_map(resp);
    auto ad = parse_auth_data(as_bstr(m[2]));
    REQUIRE((ad.flags & 0x80) != 0);
    auto exts = split_text_map(ad.extensions);
    REQUIRE(exts.count("hmac-secret") == 1);
    return decrypt(as_bstr(exts["hmac-secret"]));
  }
};

std::vector<std::uint8_t> make_with_hmac(Rig& rig) {
  MakeCredOpts o;
  o.hmac_create_secret = true;
  auto r = rig.call(make_cred_request(o));
  REQUIRE(r.has_value());
  auto m = split_int_map(*r);
  auto ad = parse_auth_data(as_bstr(m[2]));
  REQUIRE((ad.flags & 0x80) != 0);
  auto exts = split_text_map(ad.extensions);
  cbor::Reader rd(exts["hmac-secret"]);
  REQUIRE(*rd.boolean() == true);
  return ad.cred_id;
}

}  // namespace

TEST_CASE("hmac-secret: create output, deterministic outputs, two salts", "[hmac]") {
  Rig rig;
  auto id = make_with_hmac(rig);
  HmacClient c(rig);
  std::vector<std::uint8_t> s1(32, 0x11), s2(32, 0x22);
  GetAssertOpts g;
  g.allow = std::vector<std::vector<std::uint8_t>>{id};
  g.hmac_secret_ext = c.ext(s1);
  auto r1 = rig.call(get_assert_request(g));
  REQUIRE(r1.has_value());
  auto o1 = c.outputs(*r1);
  REQUIRE(o1.size() == 32);
  g.hmac_secret_ext = c.ext(s1);
  auto o1b = c.outputs(*rig.call(get_assert_request(g)));
  REQUIRE(o1 == o1b);
  std::vector<std::uint8_t> both(s1);
  both.insert(both.end(), s2.begin(), s2.end());
  g.hmac_secret_ext = c.ext(both);
  auto o2 = c.outputs(*rig.call(get_assert_request(g)));
  REQUIRE(o2.size() == 64);
  REQUIRE(std::vector<std::uint8_t>(o2.begin(), o2.begin() + 32) == o1);
  // Different credential → different output.
  auto id2 = make_with_hmac(rig);
  g.allow = std::vector<std::vector<std::uint8_t>>{id2};
  g.hmac_secret_ext = c.ext(s1);
  REQUIRE(c.outputs(*rig.call(get_assert_request(g))) != o1);
  // A credential created WITHOUT the extension still has credRandom.
  auto plain = rig.register_cred();
  g.allow = std::vector<std::vector<std::uint8_t>>{plain};
  g.hmac_secret_ext = c.ext(s1);
  REQUIRE(c.outputs(*rig.call(get_assert_request(g))).size() == 32);
}

TEST_CASE("hmac-secret: UV selects the other credRandom", "[hmac]") {
  Rig rig;
  auto id = make_with_hmac(rig);
  HmacClient c(rig);
  std::vector<std::uint8_t> s1(32, 0x33);
  GetAssertOpts g;
  g.allow = std::vector<std::vector<std::uint8_t>>{id};
  g.hmac_secret_ext = c.ext(s1);
  auto no_uv = c.outputs(*rig.call(get_assert_request(g)));
  // Set a PIN and get a token through the same shared secret machinery.
  {
    std::vector<std::uint8_t> padded(64, 0);
    std::memcpy(padded.data(), "1234", 4);
    auto enc = c.encrypt(padded);
    auto mac = *rig.crypto.hmac_sha256(c.hmac_key, enc);
    std::vector<Entry> e = {{Writer::encode_uint(1), Writer::encode_uint(2)}, {Writer::encode_uint(2), Writer::encode_uint(3)},
                            {Writer::encode_uint(3), c.cose()}, {Writer::encode_uint(4), Writer::encode_bstr(mac)},
                            {Writer::encode_uint(5), Writer::encode_bstr(enc)}};
    Writer w;
    w.write_map(e);
    auto b = w.finish();
    b.insert(b.begin(), ctap::kCmdClientPin);
    REQUIRE(rig.call(b).has_value());
  }
  std::vector<std::uint8_t> token;
  {
    auto d = rig.crypto.sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("1234"), 4));
    std::vector<std::uint8_t> h(d.begin(), d.begin() + 16);
    auto henc = c.encrypt(h);
    std::vector<Entry> e = {{Writer::encode_uint(1), Writer::encode_uint(2)}, {Writer::encode_uint(2), Writer::encode_uint(9)},
                            {Writer::encode_uint(3), c.cose()}, {Writer::encode_uint(6), Writer::encode_bstr(henc)},
                            {Writer::encode_uint(9), Writer::encode_uint(2)}};
    Writer w;
    w.write_map(e);
    auto b = w.finish();
    b.insert(b.begin(), ctap::kCmdClientPin);
    auto r = rig.call(b);
    REQUIRE(r.has_value());
    token = c.decrypt(as_bstr(split_int_map(*r)[2]));
  }
  GetAssertOpts gu;
  gu.allow = g.allow;
  gu.hmac_secret_ext = c.ext(s1);
  auto mac = *rig.crypto.hmac_sha256(token, gu.client_data_hash);
  gu.pin_auth = std::vector<std::uint8_t>(mac.begin(), mac.end());
  gu.pin_protocol = 2;
  auto r = rig.call(get_assert_request(gu));
  REQUIRE(r.has_value());
  REQUIRE((parse_auth_data(as_bstr(split_int_map(*r)[2])).flags & 0x04) != 0);
  auto with_uv = c.outputs(*r);
  REQUIRE(with_uv != no_uv);
  gu.hmac_secret_ext = c.ext(s1);
  mac = *rig.crypto.hmac_sha256(token, gu.client_data_hash);
  gu.pin_auth = std::vector<std::uint8_t>(mac.begin(), mac.end());
  REQUIRE(c.outputs(*rig.call(get_assert_request(gu))) == with_uv);
}

TEST_CASE("hmac-secret: errors and getNextAssertion", "[hmac]") {
  Rig rig;
  MakeCredOpts a;
  a.user_id = bytes({1});
  auto id_a = rig.register_cred(a);
  MakeCredOpts b;
  b.user_id = bytes({2});
  auto id_b = rig.register_cred(b);
  HmacClient c(rig);
  std::vector<std::uint8_t> s1(32, 0x44);
  GetAssertOpts g;
  g.hmac_secret_ext = c.ext(s1, /*corrupt_auth=*/true);
  REQUIRE(rig.call(get_assert_request(g)).error() == Status::ExtensionFirst);
  g.hmac_secret_ext = c.ext(s1, false, 1);
  REQUIRE(rig.call(get_assert_request(g)).error() == Status::InvalidParameter);
  std::vector<std::uint8_t> bad_len(48, 1);
  g.hmac_secret_ext = c.ext(bad_len);
  REQUIRE(rig.call(get_assert_request(g)).error() == Status::InvalidParameter);
  // Discoverable flow: both credentials get their own output.
  g.hmac_secret_ext = c.ext(s1);
  auto r1 = rig.call(get_assert_request(g));
  REQUIRE(r1.has_value());
  auto o1 = c.outputs(*r1);
  const std::uint8_t next[] = {ctap::kCmdGetNextAssertion};
  auto r2 = rig.call(std::vector<std::uint8_t>(next, next + 1));
  REQUIRE(r2.has_value());
  auto o2 = c.outputs(*r2);
  REQUIRE(o1 != o2);
  // Mixed backend: fake-TPM row unwraps through the primary backend.
  Rig hw(true);
  auto hid = make_with_hmac(hw);
  HmacClient hc(hw);
  GetAssertOpts hg;
  hg.allow = std::vector<std::vector<std::uint8_t>>{hid};
  hg.hmac_secret_ext = hc.ext(s1);
  REQUIRE(hc.outputs(*hw.call(get_assert_request(hg))).size() == 32);
}
