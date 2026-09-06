// CTAP1/U2F over CTAPHID_MSG (PR11).
#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstring>

using namespace swpk;          // NOLINT
using namespace swpk::test;    // NOLINT

namespace {

constexpr std::uint8_t kInsRegister = 0x01;
constexpr std::uint8_t kInsAuthenticate = 0x02;
constexpr std::uint8_t kInsVersion = 0x03;

// Extended-length APDU with a 2-byte Le, exactly what python-fido2 and
// libfido2 put on the wire.
std::vector<std::uint8_t> apdu_ext(std::uint8_t ins, std::uint8_t p1,
                                   std::span<const std::uint8_t> data) {
  std::vector<std::uint8_t> a{0x00, ins, p1, 0x00, 0x00,
                              static_cast<std::uint8_t>(data.size() >> 8),
                              static_cast<std::uint8_t>(data.size() & 0xFF)};
  a.insert(a.end(), data.begin(), data.end());
  a.push_back(0x00);
  a.push_back(0x00);
  return a;
}

// Short-form Lc (older stacks); no Le.
std::vector<std::uint8_t> apdu_short(std::uint8_t ins, std::uint8_t p1,
                                     std::span<const std::uint8_t> data) {
  std::vector<std::uint8_t> a{0x00, ins, p1, 0x00, static_cast<std::uint8_t>(data.size())};
  a.insert(a.end(), data.begin(), data.end());
  return a;
}

std::uint16_t status_of(const std::vector<std::uint8_t>& r) {
  REQUIRE(r.size() >= 2);
  return static_cast<std::uint16_t>((r[r.size() - 2] << 8) | r[r.size() - 1]);
}

std::vector<std::uint8_t> body_of(const std::vector<std::uint8_t>& r) {
  REQUIRE(r.size() >= 2);
  return {r.begin(), r.end() - 2};
}

struct Registration {
  std::vector<std::uint8_t> user_pub;  // 65-byte uncompressed point
  std::vector<std::uint8_t> key_handle;
  std::vector<std::uint8_t> cert_der;
  std::vector<std::uint8_t> signature;
};

Registration parse_registration(const std::vector<std::uint8_t>& b) {
  Registration r;
  REQUIRE(b.size() > 67);
  REQUIRE(b[0] == 0x05);
  r.user_pub.assign(b.begin() + 1, b.begin() + 66);
  const std::size_t kh_len = b[66];
  REQUIRE(b.size() > 67 + kh_len);
  r.key_handle.assign(b.begin() + 67, b.begin() + 67 + static_cast<std::ptrdiff_t>(kh_len));
  // DER SEQUENCE header: tag, length (short or long form).
  std::size_t off = 67 + kh_len;
  REQUIRE(b[off] == 0x30);
  std::size_t hdr = 2;
  std::size_t len = b[off + 1];
  if (len > 0x80) {
    const std::size_t n = len - 0x80;
    len = 0;
    for (std::size_t i = 0; i < n; ++i) {
      len = (len << 8) | b[off + 2 + i];
    }
    hdr = 2 + n;
  }
  REQUIRE(b.size() > off + hdr + len);
  r.cert_der.assign(b.begin() + static_cast<std::ptrdiff_t>(off),
                    b.begin() + static_cast<std::ptrdiff_t>(off + hdr + len));
  r.signature.assign(b.begin() + static_cast<std::ptrdiff_t>(off + hdr + len), b.end());
  return r;
}

crypto::P256PublicKey pub_from_point(std::span<const std::uint8_t> point) {
  crypto::P256PublicKey p{};
  REQUIRE(point.size() == 65);
  REQUIRE(point[0] == 0x04);
  std::memcpy(p.x.data(), point.data() + 1, 32);
  std::memcpy(p.y.data(), point.data() + 33, 32);
  return p;
}

crypto::P256PublicKey pub_from_cert(std::span<const std::uint8_t> der) {
  crypto::P256PublicKey out{};
  const unsigned char* p = der.data();
  X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
  REQUIRE(x != nullptr);
  EVP_PKEY* k = X509_get_pubkey(x);
  REQUIRE(k != nullptr);
  unsigned char enc[65];
  std::size_t len = sizeof(enc);
  REQUIRE(EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc, sizeof(enc),
                                          &len) == 1);
  REQUIRE(len == 65);
  std::memcpy(out.x.data(), enc + 1, 32);
  std::memcpy(out.y.data(), enc + 33, 32);
  EVP_PKEY_free(k);
  X509_free(x);
  return out;
}

std::array<std::uint8_t, 32> fill(std::uint8_t v) {
  std::array<std::uint8_t, 32> a{};
  a.fill(v);
  return a;
}

std::vector<std::uint8_t> reg_data(const std::array<std::uint8_t, 32>& challenge,
                                   const std::array<std::uint8_t, 32>& application) {
  std::vector<std::uint8_t> d(challenge.begin(), challenge.end());
  d.insert(d.end(), application.begin(), application.end());
  return d;
}

std::vector<std::uint8_t> auth_data_apdu(const std::array<std::uint8_t, 32>& challenge,
                                         const std::array<std::uint8_t, 32>& application,
                                         std::span<const std::uint8_t> key_handle) {
  std::vector<std::uint8_t> d(challenge.begin(), challenge.end());
  d.insert(d.end(), application.begin(), application.end());
  d.push_back(static_cast<std::uint8_t>(key_handle.size()));
  d.insert(d.end(), key_handle.begin(), key_handle.end());
  return d;
}

}  // namespace

TEST_CASE("u2f version, extended and short APDUs") {
  Rig rig(false, true);
  auto r = rig.u2f(apdu_ext(kInsVersion, 0x00, {}));
  REQUIRE(status_of(r) == 0x9000);
  REQUIRE(body_of(r) == std::vector<std::uint8_t>{'U', '2', 'F', '_', 'V', '2'});

  // Short form: only CLA INS P1 P2 Lc=0 (case 2S).
  r = rig.u2f(std::vector<std::uint8_t>{0x00, kInsVersion, 0x00, 0x00, 0x00});
  REQUIRE(status_of(r) == 0x9000);
  REQUIRE(body_of(r).size() == 6);

  // No trailing byte at all (case 1).
  r = rig.u2f(std::vector<std::uint8_t>{0x00, kInsVersion, 0x00, 0x00});
  REQUIRE(status_of(r) == 0x9000);
}

TEST_CASE("u2f unknown INS, bad CLA and truncated APDUs") {
  Rig rig(false, true);
  REQUIRE(status_of(rig.u2f(apdu_ext(0x42, 0x00, {}))) == 0x6D00);
  REQUIRE(status_of(rig.u2f(std::vector<std::uint8_t>{0x80, kInsVersion, 0x00, 0x00})) == 0x6E00);
  REQUIRE(status_of(rig.u2f(std::vector<std::uint8_t>{0x00, kInsVersion})) == 0x6700);
  // REGISTER with 63 bytes of data instead of 64.
  std::vector<std::uint8_t> short_body(63, 0x11);
  REQUIRE(status_of(rig.u2f(apdu_ext(kInsRegister, 0x00, short_body))) == 0x6700);
}

TEST_CASE("u2f register with UP allow") {
  Rig rig(false, true);
  const auto challenge = fill(0xC1);
  const auto application = fill(0xA2);

  auto r = rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(challenge, application)));
  REQUIRE(status_of(r) == 0x9000);
  REQUIRE(rig.presence.calls == 1);
  REQUIRE(rig.presence.seen[0].kind == ui::PresenceRequest::Kind::MakeCredential);

  const auto reg = parse_registration(body_of(r));
  REQUIRE(reg.key_handle.size() == 32);
  REQUIRE(reg.user_pub[0] == 0x04);

  // Attestation signature over 0x00 || app || challenge || keyHandle || userPub
  std::vector<std::uint8_t> signed_over{0x00};
  signed_over.insert(signed_over.end(), application.begin(), application.end());
  signed_over.insert(signed_over.end(), challenge.begin(), challenge.end());
  signed_over.insert(signed_over.end(), reg.key_handle.begin(), reg.key_handle.end());
  signed_over.insert(signed_over.end(), reg.user_pub.begin(), reg.user_pub.end());
  REQUIRE(verify_es256(pub_from_cert(reg.cert_der), signed_over, reg.signature));

  // The credential is a normal resident row keyed by the application parameter.
  auto cred = rig.store->find(application, reg.key_handle);
  REQUIRE(cred.has_value());
  REQUIRE(cred->rp_id == "u2f:" + hex(application));
  REQUIRE(cred->rp_id_hash == application);
  REQUIRE(cred->user_id.empty());
  REQUIRE(cred->sign_count == 1);
  REQUIRE(cred->pub.x == pub_from_point(reg.user_pub).x);

  // The attestation key/cert is persisted and reused by the next registration.
  auto att = rig.store->u2f_attestation();
  REQUIRE(att.has_value());
  REQUIRE(att->priv.size() == 32);
  REQUIRE(att->cert_der == reg.cert_der);

  auto r2 = rig.u2f(apdu_short(kInsRegister, 0x00, reg_data(fill(0xC2), application)));
  REQUIRE(status_of(r2) == 0x9000);
  const auto reg2 = parse_registration(body_of(r2));
  REQUIRE(reg2.cert_der == reg.cert_der);
  REQUIRE(reg2.key_handle != reg.key_handle);
  REQUIRE(rig.store->size() == 2);
}

TEST_CASE("u2f register denied") {
  Rig rig(false, true);
  rig.presence.next = ui::Decision::Deny;
  auto r = rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(fill(0x01), fill(0x02))));
  REQUIRE(status_of(r) == 0x6985);
  REQUIRE(r.size() == 2);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(!rig.store->u2f_attestation().has_value());
}

TEST_CASE("u2f authenticate") {
  Rig rig(false, true);
  const auto application = fill(0xA5);
  auto reg_resp = rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(fill(0x11), application)));
  REQUIRE(status_of(reg_resp) == 0x9000);
  const auto reg = parse_registration(body_of(reg_resp));
  const auto user_pub = pub_from_point(reg.user_pub);
  const auto challenge = fill(0x33);

  SECTION("check-only") {
    rig.presence.calls = 0;
    auto r = rig.u2f(apdu_ext(kInsAuthenticate, 0x07,
                              auth_data_apdu(challenge, application, reg.key_handle)));
    REQUIRE(status_of(r) == 0x6985);
    REQUIRE(r.size() == 2);
    REQUIRE(rig.presence.calls == 0);  // no UP for check-only
    REQUIRE(rig.store->find(application, reg.key_handle)->sign_count == 1);

    std::vector<std::uint8_t> unknown(32, 0x77);
    r = rig.u2f(apdu_ext(kInsAuthenticate, 0x07,
                         auth_data_apdu(challenge, application, unknown)));
    REQUIRE(status_of(r) == 0x6A80);
    // Known handle under a different application is also unknown.
    r = rig.u2f(apdu_ext(kInsAuthenticate, 0x07,
                         auth_data_apdu(challenge, fill(0xB6), reg.key_handle)));
    REQUIRE(status_of(r) == 0x6A80);
  }

  SECTION("enforce user presence and sign") {
    rig.presence.calls = 0;
    auto r = rig.u2f(apdu_ext(kInsAuthenticate, 0x03,
                              auth_data_apdu(challenge, application, reg.key_handle)));
    REQUIRE(status_of(r) == 0x9000);
    REQUIRE(rig.presence.calls == 1);
    REQUIRE(rig.presence.seen.back().kind == ui::PresenceRequest::Kind::GetAssertion);
    const auto b = body_of(r);
    REQUIRE(b[0] == 0x01);
    REQUIRE(b[1] == 0);
    REQUIRE(b[2] == 0);
    REQUIRE(b[3] == 0);
    REQUIRE(b[4] == 2);  // counter bumped to 2
    std::vector<std::uint8_t> signed_over(application.begin(), application.end());
    signed_over.insert(signed_over.end(), b.begin(), b.begin() + 5);
    signed_over.insert(signed_over.end(), challenge.begin(), challenge.end());
    REQUIRE(verify_es256(user_pub, signed_over, std::span<const std::uint8_t>(b).subspan(5)));
    REQUIRE(rig.store->find(application, reg.key_handle)->sign_count == 2);

    // A denied prompt neither signs nor bumps.
    rig.presence.next = ui::Decision::Deny;
    r = rig.u2f(apdu_ext(kInsAuthenticate, 0x03,
                         auth_data_apdu(challenge, application, reg.key_handle)));
    REQUIRE(status_of(r) == 0x6985);
    REQUIRE(r.size() == 2);
    REQUIRE(rig.store->find(application, reg.key_handle)->sign_count == 2);
  }

  SECTION("dont-enforce-user-presence-and-sign") {
    rig.presence.calls = 0;
    auto r = rig.u2f(apdu_ext(kInsAuthenticate, 0x08,
                              auth_data_apdu(challenge, application, reg.key_handle)));
    REQUIRE(status_of(r) == 0x9000);
    REQUIRE(rig.presence.calls == 0);  // no prompt
    const auto b = body_of(r);
    REQUIRE(b[0] == 0x00);  // user-presence byte clear
    REQUIRE(b[4] == 1);     // counter unchanged
    std::vector<std::uint8_t> signed_over(application.begin(), application.end());
    signed_over.insert(signed_over.end(), b.begin(), b.begin() + 5);
    signed_over.insert(signed_over.end(), challenge.begin(), challenge.end());
    REQUIRE(verify_es256(user_pub, signed_over, std::span<const std::uint8_t>(b).subspan(5)));
    REQUIRE(rig.store->find(application, reg.key_handle)->sign_count == 1);
  }

  SECTION("malformed and unsupported control bytes") {
    // khLen does not match the remaining data.
    auto d = auth_data_apdu(challenge, application, reg.key_handle);
    d.pop_back();
    REQUIRE(status_of(rig.u2f(apdu_ext(kInsAuthenticate, 0x03, d))) == 0x6700);
    REQUIRE(status_of(rig.u2f(apdu_ext(kInsAuthenticate, 0x03, std::vector<std::uint8_t>(10)))) ==
            0x6700);
    REQUIRE(status_of(rig.u2f(apdu_ext(kInsAuthenticate, 0x05,
                                       auth_data_apdu(challenge, application, reg.key_handle)))) ==
            0x6A86);
  }
}

TEST_CASE("u2f authenticate over a hardware backend") {
  Rig rig(true, true);
  const auto application = fill(0x5A);
  auto reg_resp = rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(fill(0x12), application)));
  REQUIRE(status_of(reg_resp) == 0x9000);
  const auto reg = parse_registration(body_of(reg_resp));
  auto cred = rig.store->find(application, reg.key_handle);
  REQUIRE(cred.has_value());
  REQUIRE(cred->backend == crypto::BackendKind::Tpm2);
  REQUIRE(cred->priv.empty());
  REQUIRE(!cred->handle.empty());

  const auto challenge = fill(0x34);
  auto r = rig.u2f(apdu_ext(kInsAuthenticate, 0x03,
                            auth_data_apdu(challenge, application, reg.key_handle)));
  REQUIRE(status_of(r) == 0x9000);
  const auto b = body_of(r);
  std::vector<std::uint8_t> signed_over(application.begin(), application.end());
  signed_over.insert(signed_over.end(), b.begin(), b.begin() + 5);
  signed_over.insert(signed_over.end(), challenge.begin(), challenge.end());
  REQUIRE(verify_es256(pub_from_point(reg.user_pub), signed_over,
                       std::span<const std::uint8_t>(b).subspan(5)));
}

TEST_CASE("u2f disabled") {
  Rig rig(false, false);
  REQUIRE(status_of(rig.u2f(apdu_ext(kInsVersion, 0x00, {}))) == 0x6D00);
  REQUIRE(status_of(rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(fill(1), fill(2))))) == 0x6D00);
  REQUIRE(status_of(rig.u2f(apdu_ext(kInsAuthenticate, 0x03,
                                     auth_data_apdu(fill(1), fill(2),
                                                    std::vector<std::uint8_t>(32, 3))))) == 0x6D00);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(!rig.auth->supports_u2f());

  const auto info = rig.auth->get_info();
  REQUIRE(info.versions == std::vector<std::string>{"FIDO_2_1", "FIDO_2_0"});
}

TEST_CASE("u2f enabled advertises U2F_V2 after the CTAP2 versions") {
  Rig rig(false, true);
  REQUIRE(rig.auth->supports_u2f());
  const auto info = rig.auth->get_info();
  REQUIRE(info.versions == std::vector<std::string>{"FIDO_2_1", "FIDO_2_0", "U2F_V2"});
}

TEST_CASE("u2f rows stay out of CTAP2 discoverable flows but work via allowList") {
  Rig rig(false, true);
  const auto challenge = fill(0xC1);
  // application == SHA-256("example.com"), the CTAP1-fallback mapping.
  const auto app_hash = rig.crypto.sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>("example.com"), 11));
  const std::array<std::uint8_t, 32>& application = app_hash;
  auto r = rig.u2f(apdu_ext(kInsRegister, 0x00, reg_data(challenge, application)));
  REQUIRE(status_of(r) == 0x9000);
  const auto reg = parse_registration(body_of(r));
  auto row = rig.store->find_by_id(reg.key_handle);
  REQUIRE(row.has_value());
  REQUIRE_FALSE(row->rk);

  // Discoverable getAssertion for example.com does not see it.
  GetAssertOpts g;
  REQUIRE(rig.call(get_assert_request(g)).error() == Status::NoCredentials);
  // allowList with the key handle does, and the response carries no user entity.
  g.allow = std::vector<std::vector<std::uint8_t>>{reg.key_handle};
  auto a = rig.call(get_assert_request(g));
  REQUIRE(a.has_value());
  auto m = split_int_map(*a);
  REQUIRE(m.count(4) == 0);
  // A CTAP2 registration for the same RP is not blocked by the U2F row.
  REQUIRE(rig.call(make_cred_request({})).has_value());
}
