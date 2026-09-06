#pragma once

#include "swpasskey/ctap/cancel_token.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace swpk::ui {

enum class Decision { Allow, Deny, Timeout, Cancelled };

struct PresenceRequest {
  enum class Kind { MakeCredential, GetAssertion, Reset, SetPin };
  Kind kind{Kind::GetAssertion};
  std::string rp_id;
  std::string user_display;  // may be empty
  std::array<std::uint8_t, 32> rp_id_hash{};
};

// User-presence gate. `confirm` blocks the authenticator worker; it must poll
// `cancel` (HID CANCEL) and return Cancelled promptly. The HID thread sends
// KEEPALIVE/UPNEEDED while this is outstanding.
class Presence {
public:
  virtual ~Presence() = default;
  virtual Decision confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                           std::chrono::milliseconds timeout) = 0;
  virtual const char* name() const = 0;
};

struct PresenceConfig {
  // SWPASSKEY_TESTING=1 / --testing: auto-allow. Refused in release builds.
  bool testing{false};
  // Prefer a desktop notification when available (PR8); else stdin/tty.
  bool allow_notifications{true};
};

// Always Deny. For tests and for headless daemons with no tty.
class AlwaysDenyPresence final : public Presence {
public:
  Decision confirm(const PresenceRequest&, ctap::CancelToken&,
                   std::chrono::milliseconds) override {
    return Decision::Deny;
  }
  const char* name() const override { return "deny"; }
};

// Prints the request on stderr and reads y/N from the controlling tty.
// Returns Timeout when stdin is not a tty.
class StdinPresence final : public Presence {
public:
  Decision confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                   std::chrono::milliseconds timeout) override;
  const char* name() const override { return "stdin"; }
};

#if defined(SWPASSKEY_ALLOW_TESTING_PRESENCE)
// Test-only: Allow without asking. Never compiled into release presets.
class AutoAllowPresence final : public Presence {
public:
  Decision confirm(const PresenceRequest&, ctap::CancelToken& cancel,
                   std::chrono::milliseconds) override {
    return cancel.is_cancelled() ? Decision::Cancelled : Decision::Allow;
  }
  const char* name() const override { return "auto-allow"; }
};
#endif

// Picks the best available implementation for this process (notification
// daemon when PR8 lands, otherwise stdin). Returns nullptr if `testing` is set
// in a build that does not allow AutoAllowPresence.
std::unique_ptr<Presence> make_presence(const PresenceConfig& cfg);

}  // namespace swpk::ui
