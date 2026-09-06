#pragma once

#include "swpasskey/status.hpp"

#include <filesystem>
#include <string>

namespace swpk::daemon {

// Platform data directory (DESIGN.md "Paths"):
//   Linux: $XDG_DATA_HOME/swpasskey  (default ~/.local/share/swpasskey)
//   macOS: ~/Library/Application Support/swpasskey
std::filesystem::path default_data_dir();
// Linux: $XDG_RUNTIME_DIR/swpasskey (fallback: data dir). macOS: data dir.
std::filesystem::path default_runtime_dir();
std::filesystem::path default_store_path();

// Creates `dir` (0700) if missing.
Result<void> ensure_dir(const std::filesystem::path& dir);

// 16 lowercase hex chars, generated once and stored 0600 at `sidecar`.
Result<std::string> load_or_create_serial(const std::filesystem::path& sidecar);

// Exclusive flock on `path` for the lifetime of the object. A second daemon
// fails to acquire and must exit.
class InstanceLock {
public:
  InstanceLock() = default;
  ~InstanceLock();
  InstanceLock(const InstanceLock&) = delete;
  InstanceLock& operator=(const InstanceLock&) = delete;
  InstanceLock(InstanceLock&& o) noexcept;
  InstanceLock& operator=(InstanceLock&& o) noexcept;

  static Result<InstanceLock> acquire(const std::filesystem::path& path);
  bool held() const { return fd_ >= 0; }

private:
  int fd_{-1};
};

}  // namespace swpk::daemon
