// Frozen primary template, marshalled with Tss2_MU, for a fixed seed. Golden
// computed independently (HKDF via python-cryptography + TPM2B layout).
// Needs no TPM. Any change here breaks every persisted TPM handle.
#include "tpm2_templates.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace {
std::string hex(const std::vector<std::uint8_t>& v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}
}  // namespace

TEST_CASE("TPM primary template golden", "[tpm][golden]") {
  std::array<std::uint8_t, 32> seed{};
  for (std::size_t i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(i);
  auto t = swpk::crypto::tpm2::primary_template(seed);
  REQUIRE(t.has_value());
  auto m = swpk::crypto::tpm2::marshal_public(*t);
  REQUIRE(m.has_value());
  REQUIRE(hex(*m) ==
          "003a0023000b0003047200000006008000430010000300100020"
          "fc8feeda02a87fed2ca2407a7fca1f3ce844e5c716c5e2f51ad781b9b6b44f750000");
  REQUIRE(t->publicArea.objectAttributes == 0x30472u);
  REQUIRE(t->publicArea.unique.ecc.y.size == 0);
}

TEST_CASE("TPM child and seal templates", "[tpm]") {
  auto c = swpk::crypto::tpm2::signing_child_template();
  REQUIRE((c.publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED) == 0);
  REQUIRE((c.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT) != 0);
  REQUIRE((c.publicArea.objectAttributes & TPMA_OBJECT_NODA) != 0);
  REQUIRE(c.publicArea.parameters.eccDetail.scheme.scheme == TPM2_ALG_ECDSA);
  REQUIRE(c.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg == TPM2_ALG_SHA256);
  auto s = swpk::crypto::tpm2::seal_template();
  REQUIRE(s.publicArea.type == TPM2_ALG_KEYEDHASH);
  REQUIRE((s.publicArea.objectAttributes & TPMA_OBJECT_SENSITIVEDATAORIGIN) == 0);
  REQUIRE((s.publicArea.objectAttributes & (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_RESTRICTED)) == 0);
  REQUIRE((s.publicArea.objectAttributes & TPMA_OBJECT_USERWITHAUTH) != 0);
}

TEST_CASE("TPM handle encoding round trip", "[tpm]") {
  std::vector<std::uint8_t> pub(70, 0xAA), priv(200, 0xBB);
  auto h = swpk::crypto::tpm2::encode_handle(pub, priv);
  REQUIRE(h.size() == 4 + 70 + 200);
  auto d = swpk::crypto::tpm2::decode_handle(h);
  REQUIRE(d.has_value());
  REQUIRE(d->first == pub);
  REQUIRE(d->second == priv);
  h.pop_back();
  REQUIRE_FALSE(swpk::crypto::tpm2::decode_handle(h).has_value());
  REQUIRE_FALSE(swpk::crypto::tpm2::decode_handle(std::vector<std::uint8_t>{0, 1}).has_value());
}
