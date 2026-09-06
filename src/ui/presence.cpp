#include "swpasskey/ui/presence.hpp"

#include "swpasskey/log/log.hpp"

#include <poll.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace swpk::ui {
namespace {

const char* kind_name(PresenceRequest::Kind k) {
  switch (k) {
    case PresenceRequest::Kind::MakeCredential:
      return "register (makeCredential)";
    case PresenceRequest::Kind::GetAssertion:
      return "sign in (getAssertion)";
    case PresenceRequest::Kind::Reset:
      return "FACTORY RESET";
    case PresenceRequest::Kind::SetPin:
      return "set PIN";
  }
  return "?";
}

}  // namespace

Decision StdinPresence::confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                                std::chrono::milliseconds timeout) {
  if (::isatty(STDIN_FILENO) == 0) {
    log::warn("presence_no_tty", {{"rp", req.rp_id}, {"kind", kind_name(req.kind)}});
    // No way to ask; honour the timeout so clients see UPNEEDED then ACTION_TIMEOUT.
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (cancel.is_cancelled()) {
        return Decision::Cancelled;
      }
      ::poll(nullptr, 0, 50);
    }
    return Decision::Timeout;
  }
  std::fprintf(stderr, "\n[swpasskey] %s for rp=\"%s\"%s%s — approve? [y/N] ",
               kind_name(req.kind), req.rp_id.c_str(),
               req.user_display.empty() ? "" : " user=", req.user_display.c_str());
  std::fflush(stderr);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (cancel.is_cancelled()) {
      std::fputs("\n[swpasskey] cancelled by client\n", stderr);
      return Decision::Cancelled;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      std::fputs("\n[swpasskey] timed out\n", stderr);
      return Decision::Timeout;
    }
    pollfd pfd{STDIN_FILENO, POLLIN, 0};
    const int rc = ::poll(&pfd, 1, 50);
    if (rc <= 0) {
      continue;
    }
    char buf[64];
    const ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) {
      return Decision::Timeout;
    }
    buf[n] = 0;
    return (buf[0] == 'y' || buf[0] == 'Y') ? Decision::Allow : Decision::Deny;
  }
}

std::unique_ptr<Presence> make_presence(const PresenceConfig& cfg) {
  if (cfg.testing) {
#if defined(SWPASSKEY_ALLOW_TESTING_PRESENCE)
    log::warn("presence_auto_allow", {{"warning", "SWPASSKEY_TESTING: every request is approved"}});
    return std::make_unique<AutoAllowPresence>();
#else
    log::error("presence_testing_refused", {{"reason", "release build"}});
    return nullptr;
#endif
  }
  return std::make_unique<StdinPresence>();
}

}  // namespace swpk::ui
