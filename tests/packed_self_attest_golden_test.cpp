// Golden encoding of a makeCredential response (packed self-attestation),
// produced by python-fido2 from the same fixed inputs and parsed back with
// fido2.ctap2.AttestationResponse. ECDSA is randomised, so the signature is a
// fixed placeholder; the test pins the two-layer map shape and key order.
#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "ctap_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

namespace swpk::ctap::detail {
std::vector<std::uint8_t> build_auth_data(std::span<const std::uint8_t, 32> rp_id_hash,
                                          std::uint8_t flags, std::uint32_t sign_count,
                                          std::span<const std::uint8_t> attested_cred_data,
                                          std::span<const std::uint8_t> extensions_cbor);
std::vector<std::uint8_t> build_attested_credential_data(
    std::span<const std::uint8_t, 16> aaguid, std::span<const std::uint8_t> cred_id,
    const crypto::P256PublicKey& pub);
}  // namespace swpk::ctap::detail

using namespace swpk;
using namespace swpk::test;

TEST_CASE("packed self-attestation response matches python-fido2 golden", "[golden]") {
  crypto::Provider p;
  const auto rp_hash = p.sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>("example.com"), 11));
  std::array<std::uint8_t, 32> cred_id{};
  for (std::size_t i = 0; i < 32; ++i) cred_id[i] = static_cast<std::uint8_t>(i);
  crypto::P256PublicKey pub;
  pub.x.fill(0x11);
  pub.y.fill(0x22);
  auto att = ctap::detail::build_attested_credential_data(kAaguid, cred_id, pub);
  auto ad = ctap::detail::build_auth_data(rp_hash, 0x41, 1, att, {});
  REQUIRE(hex(ad) ==
          "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce194741000000016fb1dfdd51c0"
          "43a0a6f2f74812cbf8fb0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
          "1fa5010203262001215820111111111111111111111111111111111111111111111111111111111111111122"
          "58202222222222222222222222222222222222222222222222222222222222222222");

  const auto sig = bytes({0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
  std::vector<Entry> att_stmt;
  att_stmt.emplace_back(Writer::encode_tstr("sig"), Writer::encode_bstr(sig));
  att_stmt.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(-7));  // unsorted on purpose
  Writer aw;
  aw.write_map(std::move(att_stmt));
  std::vector<Entry> resp;
  resp.emplace_back(Writer::encode_uint(3), aw.finish());
  resp.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(ad));
  resp.emplace_back(Writer::encode_uint(1), Writer::encode_tstr("packed"));
  Writer w;
  w.write_map(std::move(resp));
  REQUIRE(hex(w.finish()) ==
          "a301667061636b65640258a4a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
          "41000000016fb1dfdd51c043a0a6f2f74812cbf8fb0020000102030405060708090a0b0c0d0e0f1011121314"
          "15161718191a1b1c1d1e1fa50102032620012158201111111111111111111111111111111111111111111111"
          "111111111111111111225820222222222222222222222222222222222222222222222222222222222222222203"
          "a263616c672663736967483006020101020102");
}

TEST_CASE("a real makeCredential response has the golden shape", "[golden]") {
  Rig rig;
  auto r = rig.call(make_cred_request({}));
  REQUIRE(r.has_value());
  // a3 01 66 'packed' 02 58 xx <authData> 03 a2 63 'alg' 26 63 'sig' 58 xx <sig>
  REQUIRE((*r)[0] == 0xA3);
  REQUIRE((*r)[1] == 0x01);
  REQUIRE((*r)[2] == 0x66);
  REQUIRE(std::string(r->begin() + 3, r->begin() + 9) == "packed");
  REQUIRE((*r)[9] == 0x02);
  REQUIRE((*r)[10] == 0x58);
  const std::size_t ad_len = (*r)[11];
  const std::size_t off = 12 + ad_len;
  REQUIRE((*r)[off] == 0x03);
  REQUIRE((*r)[off + 1] == 0xA2);
  REQUIRE((*r)[off + 2] == 0x63);
  REQUIRE(std::string(r->begin() + static_cast<std::ptrdiff_t>(off + 3), r->begin() + static_cast<std::ptrdiff_t>(off + 6)) == "alg");
  REQUIRE((*r)[off + 6] == 0x26);
  REQUIRE((*r)[off + 7] == 0x63);
  REQUIRE(std::string(r->begin() + static_cast<std::ptrdiff_t>(off + 8), r->begin() + static_cast<std::ptrdiff_t>(off + 11)) == "sig");
  REQUIRE((*r)[off + 11] == 0x58);
}
