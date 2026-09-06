// Self-signed P-256 X.509 certificate for U2F attestation (DESIGN.md
// "CTAP1/U2F (PR11)"). OpenSSL C API only, no exceptions.
#include "swpasskey/crypto/provider.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <memory>
#include <string>

namespace swpk::crypto {
namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

struct X509Del {
  void operator()(X509* x) const { X509_free(x); }
};
using CertPtr = std::unique_ptr<X509, X509Del>;

// Same construction as SoftwareKeyBackend::load: OpenSSL 3 `EVP_PKEY_fromdata`
// with priv+pub is avoided deliberately (see STATUS.md "Deviations").
Pkey pkey_from_scalar_and_pub(std::span<const std::uint8_t, 32> scalar,
                              const P256PublicKey& pub) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BIGNUM* x = BN_bin2bn(pub.x.data(), 32, nullptr);
  BIGNUM* y = BN_bin2bn(pub.y.data(), 32, nullptr);
  const bool ok = ec != nullptr && d != nullptr && x != nullptr && y != nullptr &&
                  EC_KEY_set_private_key(ec, d) == 1 &&
                  EC_KEY_set_public_key_affine_coordinates(ec, x, y) == 1;
  BN_clear_free(d);
  BN_free(x);
  BN_free(y);
  if (!ok) {
    EC_KEY_free(ec);
    return nullptr;
  }
  EVP_PKEY* raw = EVP_PKEY_new();
  if (raw == nullptr || EVP_PKEY_assign_EC_KEY(raw, ec) != 1) {
    EVP_PKEY_free(raw);
    EC_KEY_free(ec);
    return nullptr;
  }
  return Pkey{raw};  // owns `ec`
}

}  // namespace

Result<std::vector<std::uint8_t>> make_self_signed_p256_cert(
    std::span<const std::uint8_t, 32> scalar, const P256PublicKey& pub,
    std::string_view subject_cn) {
  auto pkey = pkey_from_scalar_and_pub(scalar, pub);
  if (!pkey) {
    return std::unexpected(Status::Other);
  }
  CertPtr cert(X509_new());
  if (!cert) {
    return std::unexpected(Status::Other);
  }
  constexpr long kTwentyYears = 20L * 365L * 24L * 60L * 60L;
  const std::string cn(subject_cn);
  X509_NAME* name = X509_get_subject_name(cert.get());
  if (name == nullptr || X509_set_version(cert.get(), 2 /* v3 */) != 1 ||
      ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1 ||
      X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(cert.get()), kTwentyYears) == nullptr ||
      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                                 0) != 1 ||
      X509_set_issuer_name(cert.get(), name) != 1 ||
      X509_set_pubkey(cert.get(), pkey.get()) != 1 ||
      X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0) {
    return std::unexpected(Status::Other);
  }
  unsigned char* der = nullptr;
  const int len = i2d_X509(cert.get(), &der);
  if (len <= 0 || der == nullptr) {
    OPENSSL_free(der);
    return std::unexpected(Status::Other);
  }
  std::vector<std::uint8_t> out(der, der + len);
  OPENSSL_free(der);
  return out;
}

}  // namespace swpk::crypto
