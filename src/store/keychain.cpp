#include "swpasskey/store/keychain.hpp"

#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace swpk::store {
namespace {

class FileKeychain final : public Keychain {
public:
  explicit FileKeychain(std::filesystem::path p) : path_(std::move(p)) {}

  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view) override {
    const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      if (errno == ENOENT) {
        return std::optional<std::array<std::uint8_t, 32>>{};
      }
      return std::unexpected(Status::Other);
    }
    std::array<std::uint8_t, 32> dek{};
    const ssize_t n = ::read(fd, dek.data(), dek.size());
    ::close(fd);
    if (n != 32) {
      log::error("dek_file_corrupt", {{"path", path_.string()}});
      return std::unexpected(Status::Other);
    }
    return std::optional<std::array<std::uint8_t, 32>>{dek};
  }

  Result<void> store_dek(std::string_view, std::span<const std::uint8_t, 32> dek) override {
    const auto tmp = path_.string() + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
      return std::unexpected(Status::Other);
    }
    const ssize_t n = ::write(fd, dek.data(), dek.size());
    ::fsync(fd);
    ::close(fd);
    if (n != 32 || ::rename(tmp.c_str(), path_.c_str()) != 0) {
      ::unlink(tmp.c_str());
      return std::unexpected(Status::Other);
    }
    return {};
  }

  Result<void> delete_dek(std::string_view) override {
    // Best-effort zero-overwrite before unlink.
    const int fd = ::open(path_.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
      std::array<std::uint8_t, 32> zero{};
      (void)!::write(fd, zero.data(), zero.size());
      ::fsync(fd);
      ::close(fd);
    }
    ::unlink(path_.c_str());
    return {};
  }

  const char* name() const override { return "file"; }

private:
  std::filesystem::path path_;
};

class FallbackKeychain final : public Keychain {
public:
  FallbackKeychain(std::unique_ptr<Keychain> primary, std::unique_ptr<Keychain> fallback)
      : primary_(std::move(primary)), fallback_(std::move(fallback)) {}

  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view id) override {
    if (primary_ && !degraded_) {
      auto r = primary_->load_dek(id);
      if (r) {
        if (r->has_value()) {
          return r;
        }
        // Not in the primary: check the fallback file (earlier degraded run).
        auto f = fallback_->load_dek(id);
        if (f && f->has_value()) {
          log::warn("dek_found_in_fallback_only", {{"fallback", fallback_->name()}});
          degraded_ = true;
        }
        return f;
      }
      degrade();
    }
    return fallback_->load_dek(id);
  }

  Result<void> store_dek(std::string_view id, std::span<const std::uint8_t, 32> dek) override {
    if (primary_ && !degraded_) {
      if (primary_->store_dek(id, dek)) {
        return {};
      }
      degrade();
    }
    return fallback_->store_dek(id, dek);
  }

  Result<void> delete_dek(std::string_view id) override {
    if (primary_) {
      (void)primary_->delete_dek(id);
    }
    return fallback_->delete_dek(id);
  }

  const char* name() const override {
    return (primary_ && !degraded_) ? primary_->name() : fallback_->name();
  }

private:
  void degrade() {
    degraded_ = true;
    log::warn("keychain_unavailable_using_file_fallback",
              {{"primary", primary_ ? primary_->name() : "none"},
               {"warning", "DEK stored in a 0600 file; weaker for software creds and metadata"}});
  }
  std::unique_ptr<Keychain> primary_;
  std::unique_ptr<Keychain> fallback_;
  bool degraded_{false};
};

}  // namespace

std::unique_ptr<Keychain> make_file_keychain(std::filesystem::path path) {
  return std::make_unique<FileKeychain>(std::move(path));
}

std::unique_ptr<Keychain> make_fallback_keychain(std::unique_ptr<Keychain> primary,
                                                 std::unique_ptr<Keychain> fallback) {
  return std::make_unique<FallbackKeychain>(std::move(primary), std::move(fallback));
}

Result<std::optional<std::array<std::uint8_t, 32>>> MemoryKeychain::load_dek(std::string_view id) {
  if (fail) {
    return std::unexpected(Status::Other);
  }
  if (dek_ && id_ == id) {
    return dek_;
  }
  return std::optional<std::array<std::uint8_t, 32>>{};
}

Result<void> MemoryKeychain::store_dek(std::string_view id, std::span<const std::uint8_t, 32> dek) {
  if (fail) {
    return std::unexpected(Status::Other);
  }
  id_ = std::string(id);
  std::array<std::uint8_t, 32> d{};
  std::copy(dek.begin(), dek.end(), d.begin());
  dek_ = d;
  return {};
}

Result<void> MemoryKeychain::delete_dek(std::string_view) {
  dek_.reset();
  return {};
}

}  // namespace swpk::store
