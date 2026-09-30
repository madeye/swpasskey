#include "swpasskey/ui/presence.hpp"

#include "presence_util.hpp"
#include "swpasskey/log/log.hpp"

#include <poll.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace swpk::ui {

namespace detail {

const char* kind_name(PresenceRequest::Kind k) {
  switch (k) {
    case PresenceRequest::Kind::MakeCredential:
      return "Create a passkey";
    case PresenceRequest::Kind::GetAssertion:
      return "Sign in";
    case PresenceRequest::Kind::Reset:
      return "Erase all passkeys";
    case PresenceRequest::Kind::SetPin:
      return "Set a PIN";
    case PresenceRequest::Kind::Selection:
      return "Use this security key";
  }
  return "?";
}

const char* kind_action(PresenceRequest::Kind k) {
  switch (k) {
    case PresenceRequest::Kind::MakeCredential:
      return "creating a passkey";
    case PresenceRequest::Kind::GetAssertion:
      return "signing in";
    case PresenceRequest::Kind::Reset:
      return "erasing all passkeys";
    case PresenceRequest::Kind::SetPin:
      return "setting a PIN";
    case PresenceRequest::Kind::Selection:
      return "using this security key";
  }
  return "?";
}

std::string clamp_text(const std::string& s, std::size_t max) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    const auto u = static_cast<unsigned char>(c);
    out.push_back((u < 0x20 || u == 0x7F) ? ' ' : c);
  }
  if (out.size() <= max) {
    return out;
  }
  // Never cut a UTF-8 sequence in half: back off over continuation bytes.
  std::size_t n = max;
  while (n > 0 && (static_cast<unsigned char>(out[n]) & 0xC0) == 0x80) {
    --n;
  }
  out.resize(n);
  out += "...";
  return out;
}

}  // namespace detail

namespace {

using detail::kind_name;

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
  // Client-controlled text: strip control characters so escape sequences
  // cannot rewrite the prompt line.
  const std::string rp = detail::clamp_text(req.rp_id);
  const std::string user = detail::clamp_text(req.user_display);
  if (rp.empty()) {
    std::fprintf(stderr, "\n[swpasskey] %s? [y/N] ", kind_name(req.kind));
  } else {
    std::fprintf(stderr, "\n[swpasskey] %s on \"%s\"%s%s? [y/N] ",
                 kind_name(req.kind), rp.c_str(), user.empty() ? "" : " as ", user.c_str());
  }
  std::fflush(stderr);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (cancel.is_cancelled()) {
      std::fputs("\n[swpasskey] The request was canceled.\n", stderr);
      return Decision::Cancelled;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      std::fputs("\n[swpasskey] The request timed out.\n", stderr);
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

#if !defined(__APPLE__) && !defined(SWPASSKEY_LIBNOTIFY)
// No platform prompt in this build (Linux without libnotify at configure time).
std::unique_ptr<Presence> make_desktop_presence() {
  log::warn("presence_notify_unavailable", {{"reason", "built without libnotify"}});
  return nullptr;
}
#endif

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

  std::string prefer = cfg.prefer.empty() ? std::string("auto") : cfg.prefer;
  if (prefer != "auto" && prefer != "stdin" && prefer != "notify" && prefer != "alert") {
    log::warn("presence_prefer_unknown", {{"value", prefer}, {"using", "auto"}});
    prefer = "auto";
  }
  if (prefer == "stdin") {
    return std::make_unique<StdinPresence>();
  }
  // "notify"/"alert" ask for the desktop prompt explicitly; "auto" follows the
  // config. Failing to build one is never fatal: fall back to the tty prompt.
  if (prefer != "auto" || cfg.allow_notifications) {
    if (auto desktop = make_desktop_presence()) {
      return desktop;
    }
    log::warn("presence_notify_unavailable", {{"fallback", "stdin"}});
  }
  return std::make_unique<StdinPresence>();
}

}  // namespace swpk::ui
