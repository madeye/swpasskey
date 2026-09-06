#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include <array>
#include <cstring>
#include <memory>

namespace swpk::crypto {
namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

class SoftwareSigningKey final : public SigningKey {
public:
  SoftwareSigningKey(Pkey pkey, P256PublicKey pub, std::array<std::uint8_t, 32> scalar)
      : pkey_(std::move(pkey)), pub_(pub), scalar_(scalar) {}

  BackendKind kind() const override { return BackendKind::Software; }

  P256PublicKey pub() const override { return pub_; }

  Result<std::vector<std::uint8_t>> sign_der(
      std::span<const std::uint8_t> message) const override {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
      return std::unexpected(Status::Other);
    }
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey_.get()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    std::size_t len = 0;
    if (EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    std::vector<std::uint8_t> der(len);
    if (EVP_DigestSign(ctx, der.data(), &len, message.data(), message.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      return std::unexpected(Status::Other);
    }
    EVP_MD_CTX_free(ctx);
    der.resize(len);
    auto norm = Provider::ecdsa_p256_der_normalize_low_s(der);
    if (!norm) {
      return std::unexpected(norm.error());
    }
    return *norm;
  }

  std::vector<std::uint8_t> persist_handle() const override { return {}; }

  std::array<std::uint8_t, 32> export_scalar() const { return scalar_; }

  ~SoftwareSigningKey() override { OPENSSL_cleanse(scalar_.data(), scalar_.size()); }

private:
  Pkey pkey_;
  P256PublicKey pub_{};
  std::array<std::uint8_t, 32> scalar_{};
};

Result<std::array<std::uint8_t, 32>> scalar_from_pkey(EVP_PKEY* pkey) {
  BIGNUM* bn = nullptr;
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != 1 || bn == nullptr) {
    return std::unexpected(Status::Other);
  }
  std::array<std::uint8_t, 32> out{};
  const int n = BN_bn2binpad(bn, out.data(), 32);
  BN_clear_free(bn);
  if (n != 32) {
    OPENSSL_cleanse(out.data(), out.size());
    return std::unexpected(Status::Other);
  }
  return out;
}

P256PublicKey pub_from_pkey(EVP_PKEY* pkey) {
  P256PublicKey out;
  std::uint8_t enc[65];
  std::size_t len = sizeof(enc);
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc, sizeof(enc),
                                      &len) != 1 ||
      len != 65 || enc[0] != 0x04) {
    return out;
  }
  std::memcpy(out.x.data(), enc + 1, 32);
  std::memcpy(out.y.data(), enc + 33, 32);
  return out;
}

Result<Pkey> pkey_from_scalar_and_pub(std::span<const std::uint8_t, 32> scalar,
                                      const P256PublicKey& pub) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BIGNUM* x = BN_bin2bn(pub.x.data(), 32, nullptr);
  BIGNUM* y = BN_bin2bn(pub.y.data(), 32, nullptr);
  if (!ec || !d || !x || !y || EC_KEY_set_private_key(ec, d) != 1 ||
      EC_KEY_set_public_key_affine_coordinates(ec, x, y) != 1) {
    BN_clear_free(d);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
    return std::unexpected(Status::Other);
  }
  BN_clear_free(d);
  BN_free(x);
  BN_free(y);
  EVP_PKEY* raw = EVP_PKEY_new();
  if (!raw || EVP_PKEY_assign_EC_KEY(raw, ec) != 1) {
    EVP_PKEY_free(raw);
    EC_KEY_free(ec);
    return std::unexpected(Status::Other);
  }
  return Pkey{raw};
}

}  // namespace

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::generate() {
  EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (!raw) {
    return std::unexpected(Status::Other);
  }
  auto pub = pub_from_pkey(raw);
  auto sc = scalar_from_pkey(raw);
  if (!sc) {
    EVP_PKEY_free(raw);
    return std::unexpected(sc.error());
  }
  return std::make_unique<SoftwareSigningKey>(Pkey{raw}, pub, *sc);
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load(
    std::span<const std::uint8_t> handle, const P256PublicKey& pub) {
  if (handle.size() != 32) {
    return std::unexpected(Status::InvalidParameter);
  }
  std::array<std::uint8_t, 32> sc{};
  std::memcpy(sc.data(), handle.data(), 32);
  auto p = pkey_from_scalar_and_pub(sc, pub);
  if (!p) {
    return std::unexpected(p.error());
  }
  std::array<std::uint8_t, 32> sca{};
  std::memcpy(sca.data(), handle.data(), 32);
  return std::make_unique<SoftwareSigningKey>(std::move(*p), pub, sca);
}

Result<P256PublicKey> p256_pub_from_scalar(std::span<const std::uint8_t, 32> scalar) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* pt = group != nullptr ? EC_POINT_new(group) : nullptr;
  P256PublicKey out{};
  bool ok = group != nullptr && d != nullptr && ctx != nullptr && pt != nullptr &&
            EC_POINT_mul(group, pt, d, nullptr, nullptr, ctx) == 1;
  if (ok) {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    ok = x != nullptr && y != nullptr &&
         EC_POINT_get_affine_coordinates(group, pt, x, y, ctx) == 1 &&
         BN_bn2binpad(x, out.x.data(), 32) == 32 && BN_bn2binpad(y, out.y.data(), 32) == 32;
    BN_free(x);
    BN_free(y);
  }
  EC_POINT_free(pt);
  BN_CTX_free(ctx);
  BN_clear_free(d);
  EC_GROUP_free(group);
  if (!ok) {
    OPENSSL_cleanse(out.x.data(), out.x.size());
    OPENSSL_cleanse(out.y.data(), out.y.size());
    return std::unexpected(Status::Other);
  }
  return out;
}

Result<std::unique_ptr<SigningKey>> SoftwareKeyBackend::load_from_scalar(
    std::span<const std::uint8_t, 32> scalar) {
  auto pub = p256_pub_from_scalar(scalar);
  if (!pub) {
    return std::unexpected(pub.error());
  }
  return load(scalar, *pub);
}

Result<void> SoftwareKeyBackend::destroy(std::span<const std::uint8_t>) { return {}; }

Result<std::vector<std::uint8_t>> SoftwareKeyBackend::wrap_secret(
    std::span<const std::uint8_t> secret) {
  return std::vector<std::uint8_t>(secret.begin(), secret.end());
}

Result<std::vector<std::uint8_t>> SoftwareKeyBackend::unwrap_secret(
    std::span<const std::uint8_t> wrapped) {
  return std::vector<std::uint8_t>(wrapped.begin(), wrapped.end());
}

Result<std::array<std::uint8_t, 32>> SoftwareKeyBackend::export_scalar_for_store(
    const SigningKey& key) {
  if (key.kind() != BackendKind::Software) {
    return std::unexpected(Status::InvalidParameter);
  }
  return static_cast<const SoftwareSigningKey&>(key).export_scalar();
}

}  // namespace swpk::crypto
