#pragma once

#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/cancel_token.hpp"
#include "swpasskey/ctap/get_info.hpp"
#include "swpasskey/ctap/request_handler.hpp"
#include "swpasskey/status.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/ui/presence.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

namespace swpk::ctap {

inline constexpr std::uint8_t kCmdMakeCredential = 0x01;
inline constexpr std::uint8_t kCmdGetAssertion = 0x02;
inline constexpr std::uint8_t kCmdGetInfo = 0x04;
inline constexpr std::uint8_t kCmdClientPin = 0x06;
inline constexpr std::uint8_t kCmdReset = 0x07;
inline constexpr std::uint8_t kCmdGetNextAssertion = 0x08;

struct AuthenticatorConfig {
  std::array<std::uint8_t, 16> aaguid{kAaguid};
  std::chrono::milliseconds up_timeout{kUserActionTimeout};
  bool u2f_enabled{false};  // PR11
};

struct AuthenticatorMetrics {
  std::uint64_t make_cred_ok{0}, make_cred_err{0};
  std::uint64_t get_assert_ok{0}, get_assert_err{0};
  std::uint64_t up_allow{0}, up_deny{0}, up_timeout{0}, up_cancel{0};
  std::uint64_t pin_fail{0}, pin_block{0};
  std::array<std::uint64_t, 256> ctap_status{};
};

class Authenticator final : public RequestHandler {
public:
  Authenticator(AuthenticatorConfig cfg,
                crypto::Provider& crypto,
                crypto::KeyBackend& primary_keys,   // new makeCredential
                crypto::KeyBackend& software_keys,  // legacy rows; may alias primary
                store::CredentialStore& store,
                ui::Presence& presence);

  Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t> request,
                                                CancelToken& cancel) override;
  std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t> request,
                                       CancelToken& cancel) override;
  bool supports_u2f() const override { return cfg_.u2f_enabled; }

  GetInfoSnapshot get_info() const;
  AuthenticatorMetrics metrics() const;
  const char* primary_backend_name() const;

private:
  Result<std::vector<std::uint8_t>> cmd_get_info();

  AuthenticatorConfig cfg_;
  [[maybe_unused]] crypto::Provider& crypto_;    // used from PR4
  crypto::KeyBackend& primary_;
  [[maybe_unused]] crypto::KeyBackend& software_;  // used from PR4
  store::CredentialStore& store_;
  [[maybe_unused]] ui::Presence& presence_;      // used from PR4
  mutable std::mutex metrics_mu_;
  AuthenticatorMetrics metrics_;
};

}  // namespace swpk::ctap
