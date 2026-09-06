#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <vector>

TEST_CASE("software generate/sign/verify", "[key]") {
  swpk::crypto::SoftwareKeyBackend b;
  auto key = b.generate();
  REQUIRE(key.has_value());
  REQUIRE((*key)->kind() == swpk::crypto::BackendKind::Software);
  REQUIRE((*key)->persist_handle().empty());
  const std::uint8_t msg[] = {'t', 'e', 's', 't'};
  auto sig = (*key)->sign_der(msg);
  REQUIRE(sig.has_value());
  REQUIRE_FALSE(sig->empty());

  auto pub = (*key)->pub();
  std::uint8_t enc[65];
  enc[0] = 0x04;
  std::memcpy(enc + 1, pub.x.data(), 32);
  std::memcpy(enc + 33, pub.y.data(), 32);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("P-256"), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, enc, sizeof(enc)),
      OSSL_PARAM_construct_end()};
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  REQUIRE(ctx != nullptr);
  EVP_PKEY* pkey = nullptr;
  REQUIRE(EVP_PKEY_fromdata_init(ctx) > 0);
  REQUIRE(EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0);
  EVP_PKEY_CTX_free(ctx);
  EVP_MD_CTX* mctx = EVP_MD_CTX_new();
  REQUIRE(EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, pkey) == 1);
  REQUIRE(EVP_DigestVerify(mctx, sig->data(), sig->size(), msg, sizeof(msg)) == 1);
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_free(pkey);
}

TEST_CASE("export and reload scalar", "[key]") {
  swpk::crypto::SoftwareKeyBackend b;
  auto key = b.generate();
  REQUIRE(key.has_value());
  auto sc = swpk::crypto::SoftwareKeyBackend::export_scalar_for_store(**key);
  REQUIRE(sc.has_value());
  auto loaded = b.load(*sc, (*key)->pub());
  REQUIRE(loaded.has_value());
  REQUIRE((*loaded)->pub().x == (*key)->pub().x);
  const std::uint8_t msg[] = {1, 2, 3};
  REQUIRE((*loaded)->sign_der(msg).has_value());
}

TEST_CASE("wrap_secret is identity", "[key]") {
  swpk::crypto::SoftwareKeyBackend b;
  const std::uint8_t s[] = {1, 2, 3};
  auto w = b.wrap_secret(s);
  REQUIRE(w.has_value());
  REQUIRE(*w == std::vector<std::uint8_t>({1, 2, 3}));
}

TEST_CASE("probe software", "[key]") {
  auto b = swpk::crypto::probe_key_backend("software");
  REQUIRE(b != nullptr);
  REQUIRE(b->kind() == swpk::crypto::BackendKind::Software);
  REQUIRE(swpk::crypto::probe_key_backend("tpm") == nullptr);
}
