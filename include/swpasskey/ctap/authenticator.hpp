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
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
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
  // PIN protocol: base delay after 3 consecutive failures (5 s, 10 s, ... cap 60 s)
  // and the pinUvAuthToken idle timeout. Tests shrink these.
  std::chrono::milliseconds pin_failure_delay_base{5000};
  std::chrono::milliseconds pin_token_idle_timeout{30000};
};

struct AuthenticatorMetrics {
  std::uint64_t make_cred_ok{0}, make_cred_err{0};
  std::uint64_t get_assert_ok{0}, get_assert_err{0};
  std::uint64_t up_allow{0}, up_deny{0}, up_timeout{0}, up_cancel{0};
  std::uint64_t pin_fail{0}, pin_block{0};
  std::array<std::uint64_t, 256> ctap_status{};
};

namespace detail {
struct AssertionState;
struct ExtensionsIn;
struct UserEntity;
class PinManager;
}  // namespace detail

class Authenticator final : public RequestHandler {
public:
  Authenticator(AuthenticatorConfig cfg,
                crypto::Provider& crypto,
                crypto::KeyBackend& primary_keys,   // new makeCredential
                crypto::KeyBackend& software_keys,  // legacy rows; may alias primary
                store::CredentialStore& store,
                ui::Presence& presence);
  ~Authenticator() override;

  Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t> request,
                                                CancelToken& cancel) override;
  std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t> request,
                                       CancelToken& cancel) override;
  bool supports_u2f() const override { return cfg_.u2f_enabled; }

  GetInfoSnapshot get_info() const;
  AuthenticatorMetrics metrics() const;
  const char* primary_backend_name() const;

  // Control-socket entry points (PR12). `reset` still requires local UP.
  Result<void> ctl_reset(CancelToken& cancel);

private:
  struct PinAuthIn {
    std::optional<std::vector<std::uint8_t>> param;  // pinUvAuthParam
    std::optional<std::uint64_t> protocol;           // pinUvAuthProtocol
  };

  Result<std::vector<std::uint8_t>> cmd_get_info();
  Result<std::vector<std::uint8_t>> cmd_make_credential(std::span<const std::uint8_t> body,
                                                        CancelToken& cancel);
  Result<std::vector<std::uint8_t>> cmd_get_assertion(std::span<const std::uint8_t> body,
                                                      CancelToken& cancel);
  Result<std::vector<std::uint8_t>> cmd_get_next_assertion();
  Result<std::vector<std::uint8_t>> cmd_reset(CancelToken& cancel);
  Result<std::vector<std::uint8_t>> cmd_client_pin(std::span<const std::uint8_t> body,
                                                   CancelToken& cancel);

  // Shared assertion builder used by getAssertion and getNextAssertion.
  Result<std::vector<std::uint8_t>> build_assertion(const store::Credential& cred,
                                                    std::span<const std::uint8_t, 32> rp_id_hash,
                                                    std::span<const std::uint8_t, 32> client_data_hash,
                                                    std::uint8_t flags, bool bump_counter,
                                                    const detail::ExtensionsIn* ext,
                                                    std::optional<std::size_t> number_of_credentials);

  // User presence with keepalive status bookkeeping.
  ui::Decision confirm_up(ui::PresenceRequest::Kind kind, const std::string& rp_id,
                          const std::string& user_display,
                          std::span<const std::uint8_t, 32> rp_id_hash, CancelToken& cancel);

  // pinUvAuthParam handling for make/get. Returns the UV flag to set in
  // authData. A zero-length param is the CTAP 2.1 "touch to select" probe
  // and performs UP before answering PIN_NOT_SET / PIN_INVALID.
  Result<bool> check_pin_auth(const PinAuthIn& in, std::span<const std::uint8_t, 32> client_data_hash,
                              std::uint8_t permission, const std::string& rp_id,
                              std::span<const std::uint8_t, 32> rp_id_hash, bool is_make,
                              CancelToken& cancel);

  Result<std::unique_ptr<crypto::SigningKey>> load_key(const store::Credential& cred);
  void destroy_key(const store::Credential& cred);
  static std::uint64_t now_unix();
  void count_status(std::uint8_t status);

  AuthenticatorConfig cfg_;
  crypto::Provider& crypto_;
  crypto::KeyBackend& primary_;
  crypto::KeyBackend& software_;
  store::CredentialStore& store_;
  ui::Presence& presence_;
  mutable std::mutex metrics_mu_;
  AuthenticatorMetrics metrics_;
  std::unique_ptr<detail::AssertionState> next_state_;
  std::unique_ptr<detail::PinManager> pin_;
};

}  // namespace swpk::ctap
