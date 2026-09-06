#pragma once

#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "swpasskey/store/credential.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <thread>

namespace swpk::ctl {

// Platform default: Linux $XDG_RUNTIME_DIR/swpasskey/ctl.sock,
// macOS ~/Library/Application Support/swpasskey/ctl.sock.
std::filesystem::path default_socket_path();

struct ServerDeps {
  ctap::Authenticator* auth{nullptr};
  store::CredentialStore* store{nullptr};
  daemon::Loop* loop{nullptr};  // may be null in tests
  std::string key_backend;      // probed primary
  std::string probe_detail;
  std::function<void()> quit;   // {"op":"quit"}
};

// Handles one newline-delimited JSON request; returns one JSON line (no
// trailing newline). Pure function of the request + deps; used by the socket
// server and by tests.
std::string handle_request(std::string_view line, ServerDeps& deps);

// Stats as a JSON object (also logged every 5 minutes).
std::string stats_json(ServerDeps& deps);

class UnixServer {
public:
  UnixServer(std::filesystem::path path, ServerDeps deps);
  ~UnixServer();
  Result<void> start();
  void stop();
  const std::filesystem::path& path() const { return path_; }

private:
  void run();
  std::filesystem::path path_;
  ServerDeps deps_;
  int listen_fd_{-1};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

// Client helper shared with swpasskeyctl: sends one line, returns the reply.
Result<std::string> request(const std::filesystem::path& path, std::string_view line);

}  // namespace swpk::ctl
