#pragma once

// Menu bar status item with a "Keys" window (installed credentials) and a
// "Preferences" window (launch at login, log level, daemon facts). macOS
// only; make_menu_bar() returns nullptr elsewhere or without a GUI session.
// Must be created and destroyed on the main thread, before the presence
// main loop runs.

#include "swpasskey/status.hpp"
#include "swpasskey/store/credential.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace swpk::ui {

struct MenuBarDeps {
  store::CredentialStore* store{nullptr};
  // Deletes one credential (Authenticator::ctl_delete). Called on the main
  // thread after the user confirmed.
  std::function<Result<void>(std::span<const std::uint8_t> cred_id)> delete_key;
  // Stops the daemon (loop.stop()).
  std::function<void()> quit;
  std::string version;
  std::string key_backend;  // human label, e.g. "Secure Enclave"
  std::string serial;
  std::string store_path;
  std::string ctl_socket;
};

class MenuBar {
public:
  virtual ~MenuBar() = default;
};

std::unique_ptr<MenuBar> make_menu_bar(MenuBarDeps deps);

}  // namespace swpk::ui
