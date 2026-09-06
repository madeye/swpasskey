#include "swpasskey/daemon/paths.hpp"

#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>

namespace swpk::daemon {
namespace {

std::filesystem::path home_dir() {
  if (const char* h = std::getenv("HOME"); h != nullptr && *h != 0) {
    return h;
  }
  return "/tmp";
}

}  // namespace

std::filesystem::path default_data_dir() {
#if defined(__APPLE__)
  return home_dir() / "Library" / "Application Support" / "swpasskey";
#else
  if (const char* x = std::getenv("XDG_DATA_HOME"); x != nullptr && *x != 0) {
    return std::filesystem::path(x) / "swpasskey";
  }
  return home_dir() / ".local" / "share" / "swpasskey";
#endif
}

std::filesystem::path default_runtime_dir() {
#if defined(__APPLE__)
  return default_data_dir();
#else
  if (const char* x = std::getenv("XDG_RUNTIME_DIR"); x != nullptr && *x != 0) {
    return std::filesystem::path(x) / "swpasskey";
  }
  return default_data_dir();
#endif
}

std::filesystem::path default_store_path() { return default_data_dir() / "credentials.bin"; }

Result<void> ensure_dir(const std::filesystem::path& dir) {
  std::error_code ec;
  if (std::filesystem::is_directory(dir, ec)) {
    return {};
  }
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    log::error("mkdir_failed", {{"path", dir.string()}, {"err", ec.message()}});
    return std::unexpected(Status::Other);
  }
  ::chmod(dir.c_str(), 0700);
  return {};
}

Result<std::string> load_or_create_serial(const std::filesystem::path& sidecar) {
  {
    std::ifstream in(sidecar);
    std::string s;
    if (in && std::getline(in, s)) {
      while (!s.empty() && (s.back() == '\r' || s.back() == ' ')) {
        s.pop_back();
      }
      if (s.size() == 16 && s.find_first_not_of("0123456789abcdef") == std::string::npos) {
        return s;
      }
      log::warn("serial_sidecar_invalid", {{"path", sidecar.string()}});
    }
  }
  if (auto r = ensure_dir(sidecar.parent_path()); !r) {
    return std::unexpected(r.error());
  }
  crypto::Provider rng;
  std::uint8_t raw[8];
  if (!rng.random(raw)) {
    return std::unexpected(Status::Other);
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string s;
  for (std::uint8_t b : raw) {
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0x0F]);
  }
  const int fd = ::open(sidecar.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    log::error("serial_write_failed", {{"path", sidecar.string()}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  const std::string line = s + "\n";
  const ssize_t n = ::write(fd, line.data(), line.size());
  ::fsync(fd);
  ::close(fd);
  if (n != static_cast<ssize_t>(line.size())) {
    return std::unexpected(Status::Other);
  }
  log::info("serial_created", {{"serial", s}});
  return s;
}

InstanceLock::~InstanceLock() {
  if (fd_ >= 0) {
    ::close(fd_);  // releases the flock
  }
}

InstanceLock::InstanceLock(InstanceLock&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

InstanceLock& InstanceLock::operator=(InstanceLock&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

Result<InstanceLock> InstanceLock::acquire(const std::filesystem::path& path) {
  if (auto r = ensure_dir(path.parent_path()); !r) {
    return std::unexpected(r.error());
  }
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    log::error("lock_open_failed", {{"path", path.string()}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    ::close(fd);
    log::error("already_running", {{"lock", path.string()}});
    return std::unexpected(Status::Other);
  }
  InstanceLock l;
  l.fd_ = fd;
  return l;
}

}  // namespace swpk::daemon
