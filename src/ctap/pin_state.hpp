// authenticatorClientPIN protocol 2 state (DESIGN.md "PIN protocol 2").
// Internal header.
#pragma once

#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/cancel_token.hpp"
#include "swpasskey/status.hpp"
#include "swpasskey/store/credential.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace swpk::ctap::detail {

inline constexpr std::uint8_t kPermMc = 0x01;
inline constexpr std::uint8_t kPermGa = 0x02;
inline constexpr std::uint8_t kPermCm = 0x04;
inline constexpr std::uint8_t kPermBe = 0x08;
inline constexpr std::uint8_t kPermLbw = 0x10;
inline constexpr std::uint8_t kPermAcfg = 0x20;
inline constexpr std::uint8_t kMaxRetries = 8;
inline constexpr auto kTokenIdleTimeout = std::chrono::seconds(30);

struct PinUvAuthToken {
  std::array<std::uint8_t, 32> bytes{};
  std::uint8_t permissions{};
  std::optional<std::string> permissions_rp_id;
  std::chrono::steady_clock::time_point expiry;
};

// Protocol 2 primitives shared with hmac-secret (CTAP 2.1 §6.5.4).
struct SharedSecret {
  std::array<std::uint8_t, 32> hmac_key{};
  std::array<std::uint8_t, 32> aes_key{};
  ~SharedSecret();
};
Result<SharedSecret> derive_shared_secret(crypto::Provider& p, std::span<const std::uint8_t, 32> z);
// IV(16) || AES-256-CBC(aesKey, IV, pt); pt % 16 == 0.
Result<std::vector<std::uint8_t>> pin2_encrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> pt);
Result<std::vector<std::uint8_t>> pin2_decrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> ct);
Result<std::array<std::uint8_t, 32>> pin2_authenticate(crypto::Provider& p,
                                                       std::span<const std::uint8_t> key,
                                                       std::span<const std::uint8_t> msg);

class PinManager {
public:
  PinManager(crypto::Provider& crypto, store::CredentialStore& store,
             std::chrono::milliseconds failure_delay_base = std::chrono::seconds(5),
             std::chrono::milliseconds token_idle_timeout = kTokenIdleTimeout);
  ~PinManager();

  // authenticatorClientPIN (0x06). `up` performs user presence for setPIN.
  Result<std::vector<std::uint8_t>> handle(std::span<const std::uint8_t> body, CancelToken& cancel);

  // make/get: verify pinUvAuthParam (protocol 2, full 32-byte HMAC), the
  // permission bit and the rpId binding; touches the token expiry. Returns
  // true (UV=1) on success.
  Result<bool> verify(std::span<const std::uint8_t> param, std::uint64_t protocol,
                      std::span<const std::uint8_t, 32> client_data_hash,
                      std::uint8_t permission, const std::string& rp_id);

  // ECDH against the platform key for hmac-secret (same session key).
  Result<SharedSecret> shared_secret_for(const crypto::P256PublicKey& platform_key);

  bool pin_set() const;
  std::uint8_t retries() const;
  void invalidate_token();
  // reset / PIN change: new key-agreement key + token gone.
  Result<void> regenerate_key_agreement();

  // Metrics hooks
  std::uint64_t pin_fail_count() const { return pin_fail_; }
  std::uint64_t pin_block_count() const { return pin_block_; }

private:
  Result<std::vector<std::uint8_t>> get_retries();
  Result<std::vector<std::uint8_t>> get_key_agreement();
  Result<std::vector<std::uint8_t>> set_pin(const crypto::P256PublicKey& platform_key,
                                            std::span<const std::uint8_t> new_pin_enc,
                                            std::span<const std::uint8_t> pin_auth,
                                            CancelToken& cancel);
  Result<std::vector<std::uint8_t>> change_pin(const crypto::P256PublicKey& platform_key,
                                               std::span<const std::uint8_t> pin_hash_enc,
                                               std::span<const std::uint8_t> new_pin_enc,
                                               std::span<const std::uint8_t> pin_auth,
                                               CancelToken& cancel);
  Result<std::vector<std::uint8_t>> get_token(const crypto::P256PublicKey& platform_key,
                                              std::span<const std::uint8_t> pin_hash_enc,
                                              std::uint8_t permissions,
                                              std::optional<std::string> rp_id,
                                              CancelToken& cancel);
  // Decrypts and checks pinHashEnc against the stored hash; handles retries,
  // lockout and the failure delay. Success leaves retries at 8.
  Result<void> check_pin_hash(const SharedSecret& ss, std::span<const std::uint8_t> pin_hash_enc,
                              CancelToken& cancel);
  Result<std::array<std::uint8_t, 16>> pin_from_padded(const SharedSecret& ss,
                                                       std::span<const std::uint8_t> new_pin_enc);

  crypto::Provider& crypto_;
  store::CredentialStore& store_;
  std::unique_ptr<crypto::Provider::SoftwareEcdhKey> ka_;
  std::optional<PinUvAuthToken> token_;
  std::chrono::milliseconds failure_delay_base_;
  std::chrono::milliseconds token_idle_timeout_;
  std::uint32_t consecutive_failures_{0};
  std::uint64_t pin_fail_{0};
  std::uint64_t pin_block_{0};
};

}  // namespace swpk::ctap::detail
