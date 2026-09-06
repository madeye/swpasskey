#pragma once

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace swpk::crypto {

class Provider {
public:
  Result<void> random(std::span<std::uint8_t> out);
  std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) const;
  bool consttime_equal(std::span<const std::uint8_t> a,
                       std::span<const std::uint8_t> b) const;

  Result<std::vector<std::uint8_t>> aes256gcm_encrypt(
      std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
      std::span<const std::uint8_t> aad, std::span<const std::uint8_t> pt);
  Result<std::vector<std::uint8_t>> aes256gcm_decrypt(
      std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
      std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ct_and_tag);

  Result<std::vector<std::uint8_t>> aes256cbc_encrypt(
      std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv,
      std::span<const std::uint8_t> pt);
  Result<std::vector<std::uint8_t>> aes256cbc_decrypt(
      std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv,
      std::span<const std::uint8_t> ct);

  Result<std::array<std::uint8_t, 32>> hkdf_sha256(std::span<const std::uint8_t> ikm,
                                                   std::span<const std::uint8_t> salt,
                                                   std::span<const std::uint8_t> info);
  Result<std::array<std::uint8_t, 32>> hmac_sha256(std::span<const std::uint8_t> key,
                                                   std::span<const std::uint8_t> msg);

  class SoftwareEcdhKey {
  public:
    explicit SoftwareEcdhKey(void* pkey);
    ~SoftwareEcdhKey();
    SoftwareEcdhKey(const SoftwareEcdhKey&) = delete;
    SoftwareEcdhKey& operator=(const SoftwareEcdhKey&) = delete;
    P256PublicKey pub() const;
    Result<std::array<std::uint8_t, 32>> shared_secret_x(const P256PublicKey& peer) const;

  private:
    void* pkey_{};  // EVP_PKEY*
  };

  Result<std::unique_ptr<SoftwareEcdhKey>> generate_p256_ephemeral();
  Result<std::array<std::uint8_t, 32>> p256_ecdh_x(
      std::span<const std::uint8_t, 32> our_scalar, const P256PublicKey& peer);

  static std::vector<std::uint8_t> ecdsa_p256_rs_to_der_low_s(
      std::span<const std::uint8_t, 32> r, std::span<const std::uint8_t, 32> s);
  static Result<std::vector<std::uint8_t>> ecdsa_p256_der_normalize_low_s(
      std::span<const std::uint8_t> der);
};

// Derives the P-256 public point from a private scalar. Software keys only;
// used to reload a scalar that was stored without its public key (the U2F
// attestation key, PR11).
Result<P256PublicKey> p256_pub_from_scalar(std::span<const std::uint8_t, 32> scalar);

// Self-signed P-256 X.509 certificate (SHA-256, 20-year validity) over the
// given software key. `subject_cn` becomes both the subject and the issuer CN.
// Used once for the U2F batch-attestation certificate (DESIGN.md
// "CTAP1/U2F (PR11)"): RPs that pin U2F attestation metadata will reject it.
Result<std::vector<std::uint8_t>> make_self_signed_p256_cert(
    std::span<const std::uint8_t, 32> scalar, const P256PublicKey& pub,
    std::string_view subject_cn);

}  // namespace swpk::crypto
