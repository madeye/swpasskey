// Internal helpers shared by the presence implementations (tty, libnotify,
// NSAlert). Not a public header: `src/ui/*` only.
#pragma once

#include "swpasskey/ui/presence.hpp"

#include <cstddef>
#include <string>

namespace swpk::ui::detail {

// Verbose form for the tty prompt, e.g. "register (makeCredential)".
const char* kind_name(PresenceRequest::Kind k);

// Short form for a notification title, e.g. "register" / "sign in" /
// "factory reset" / "set PIN".
const char* kind_action(PresenceRequest::Kind k);

// `rp_id` / `user_display` come from the client and are attacker-controlled.
// Drop control characters and clamp to `max` bytes on a UTF-8 boundary so the
// text cannot smuggle newlines into a notification body or break NSString.
std::string clamp_text(const std::string& s, std::size_t max = 96);

}  // namespace swpk::ui::detail
