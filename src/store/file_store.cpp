// AES-256-GCM credential store file (DESIGN.md "File format credentials.bin").
#include "swpasskey/store/file_store.hpp"

#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

namespace swpk::store {
namespace {

constexpr std::uint8_t kMagic[4] = {'S', 'W', 'P', 'K'};
constexpr std::size_t kHeaderSize = 4 + 2 + 2 + 16;  // magic version flags install_id
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;

std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

Result<std::vector<std::uint8_t>> read_file(const std::filesystem::path& p, bool& exists) {
  const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) {
      exists = false;
      return std::vector<std::uint8_t>{};
    }
    log::error("store_open_failed", {{"path", p.string()}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  exists = true;
  std::vector<std::uint8_t> out;
  std::uint8_t buf[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      return std::unexpected(Status::Other);
    }
    if (n == 0) break;
    out.insert(out.end(), buf, buf + n);
  }
  ::close(fd);
  return out;
}

Result<void> fsync_dir(const std::filesystem::path& dir) {
  const int fd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return {};  // best effort
  }
  ::fsync(fd);
  ::close(fd);
  return {};
}

Result<void> write_atomic(const std::filesystem::path& p, std::span<const std::uint8_t> data) {
  const std::string tmp = p.string() + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    log::error("store_tmp_open_failed", {{"path", tmp}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      ::unlink(tmp.c_str());
      return std::unexpected(Status::Other);
    }
    off += static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0) {
    ::close(fd);
    ::unlink(tmp.c_str());
    return std::unexpected(Status::Other);
  }
  ::close(fd);
  if (::rename(tmp.c_str(), p.c_str()) != 0) {
    log::error("store_rename_failed", {{"errno", std::strerror(errno)}});
    ::unlink(tmp.c_str());
    return std::unexpected(Status::Other);
  }
  return fsync_dir(p.parent_path());
}

class FilePersister final : public Persister {
public:
  FilePersister(std::filesystem::path path, crypto::Provider& crypto, Keychain& keychain,
                std::array<std::uint8_t, 16> install_id, std::array<std::uint8_t, 32> dek,
                int lock_fd)
      : path_(std::move(path)),
        crypto_(crypto),
        keychain_(keychain),
        install_id_(install_id),
        dek_(dek),
        lock_fd_(lock_fd) {}

  ~FilePersister() override {
    OPENSSL_cleanse(dek_.data(), dek_.size());
    if (lock_fd_ >= 0) {
      ::close(lock_fd_);
    }
  }

  Result<void> save(std::span<const std::uint8_t> plaintext) override {
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + kNonceSize + 4 + plaintext.size() + kTagSize);
    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(static_cast<std::uint8_t>(kStoreVersion));
    out.push_back(static_cast<std::uint8_t>(kStoreVersion >> 8));
    out.push_back(0);
    out.push_back(0);  // flags
    out.insert(out.end(), install_id_.begin(), install_id_.end());
    std::array<std::uint8_t, kNonceSize> nonce{};
    if (!crypto_.random(nonce)) {
      return std::unexpected(Status::Other);
    }
    auto ct = crypto_.aes256gcm_encrypt(dek_, nonce, std::span<const std::uint8_t>(out).first(kHeaderSize),
                                        plaintext);
    if (!ct) {
      return std::unexpected(Status::Other);
    }
    const std::uint32_t clen = static_cast<std::uint32_t>(ct->size() - kTagSize);
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.push_back(static_cast<std::uint8_t>(clen));
    out.push_back(static_cast<std::uint8_t>(clen >> 8));
    out.push_back(static_cast<std::uint8_t>(clen >> 16));
    out.push_back(static_cast<std::uint8_t>(clen >> 24));
    out.insert(out.end(), ct->begin(), ct->end());  // ciphertext || tag
    return write_atomic(path_, out);
  }

  Result<void> reset() override {
    // Zero-overwrite the current file in place, unlink, rotate the DEK.
    struct stat st{};
    if (::stat(path_.c_str(), &st) == 0) {
      const int fd = ::open(path_.c_str(), O_WRONLY | O_CLOEXEC);
      if (fd >= 0) {
        std::vector<std::uint8_t> zero(static_cast<std::size_t>(st.st_size));
        std::size_t off = 0;
        while (off < zero.size()) {
          const ssize_t n = ::write(fd, zero.data() + off, zero.size() - off);
          if (n <= 0) break;
          off += static_cast<std::size_t>(n);
        }
        ::fsync(fd);
        ::close(fd);
      }
      ::unlink(path_.c_str());
    }
    (void)keychain_.delete_dek(hex(install_id_));
    OPENSSL_cleanse(dek_.data(), dek_.size());
    if (!crypto_.random(dek_)) {
      return std::unexpected(Status::Other);
    }
    if (auto r = keychain_.store_dek(hex(install_id_), dek_); !r) {
      log::error("dek_store_failed_after_reset");
      return r;
    }
    log::warn("store_reset", {{"path", path_.string()}, {"dek", "rotated"}});
    return {};
  }

private:
  std::filesystem::path path_;
  crypto::Provider& crypto_;
  Keychain& keychain_;
  std::array<std::uint8_t, 16> install_id_;
  std::array<std::uint8_t, 32> dek_;
  int lock_fd_;
};

}  // namespace

Result<std::unique_ptr<CredentialStore>> open_file_store(const std::filesystem::path& path,
                                                         crypto::Provider& crypto,
                                                         Keychain& keychain) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  ::chmod(path.parent_path().c_str(), 0700);

  // Exclusive instance lock on a sidecar that is never renamed over.
  const std::string lock_path = path.string() + ".lock";
  const int lock_fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (lock_fd < 0) {
    log::error("store_lock_open_failed", {{"path", lock_path}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    ::close(lock_fd);
    log::error("already_running", {{"lock", lock_path}});
    return std::unexpected(Status::Other);
  }

  bool exists = false;
  auto file = read_file(path, exists);
  if (!file) {
    ::close(lock_fd);
    return std::unexpected(file.error());
  }

  std::array<std::uint8_t, 16> install_id{};
  std::array<std::uint8_t, 32> dek{};
  std::vector<std::uint8_t> plaintext;

  if (exists && !file->empty()) {
    const auto& f = *file;
    if (f.size() < kHeaderSize + kNonceSize + 4 + kTagSize || std::memcmp(f.data(), kMagic, 4) != 0) {
      log::error("store_bad_magic", {{"path", path.string()}});
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    const std::uint16_t version = static_cast<std::uint16_t>(f[4] | (f[5] << 8));
    if (version != kStoreVersion) {
      log::error("store_version_unsupported",
                 {{"found", std::to_string(version)}, {"speaks", std::to_string(kStoreVersion)}});
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    std::memcpy(install_id.data(), f.data() + 8, 16);
    std::array<std::uint8_t, kNonceSize> nonce{};
    std::memcpy(nonce.data(), f.data() + kHeaderSize, kNonceSize);
    const std::size_t off = kHeaderSize + kNonceSize;
    const std::uint32_t clen = static_cast<std::uint32_t>(f[off]) |
                               (static_cast<std::uint32_t>(f[off + 1]) << 8) |
                               (static_cast<std::uint32_t>(f[off + 2]) << 16) |
                               (static_cast<std::uint32_t>(f[off + 3]) << 24);
    if (f.size() != off + 4 + clen + kTagSize) {
      log::error("store_truncated", {{"path", path.string()}});
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    auto d = keychain.load_dek(hex(install_id));
    if (!d) {
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    if (!d->has_value()) {
      log::error("dek_missing", {{"install_id", hex(install_id)},
                                  {"keychain", keychain.name()},
                                  {"hint", "store exists but its DEK is gone; move credentials.bin aside to start fresh"}});
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    dek = **d;
    auto pt = crypto.aes256gcm_decrypt(dek, nonce, std::span<const std::uint8_t>(f).first(kHeaderSize),
                                       std::span<const std::uint8_t>(f).subspan(off + 4));
    if (!pt) {
      log::error("store_decrypt_failed", {{"path", path.string()}});
      OPENSSL_cleanse(dek.data(), dek.size());
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    plaintext = std::move(*pt);
  } else {
    if (!crypto.random(install_id) || !crypto.random(dek)) {
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    if (auto r = keychain.store_dek(hex(install_id), dek); !r) {
      log::error("dek_store_failed", {{"keychain", keychain.name()}});
      ::close(lock_fd);
      return std::unexpected(Status::Other);
    }
    log::info("store_created", {{"path", path.string()}, {"keychain", keychain.name()}});
  }

  auto persister = std::make_unique<FilePersister>(path, crypto, keychain, install_id, dek, lock_fd);
  OPENSSL_cleanse(dek.data(), dek.size());
  auto store = CredentialStore::open_with(plaintext, std::move(persister));
  OPENSSL_cleanse(plaintext.data(), plaintext.size());
  if (!store) {
    log::error("store_parse_failed", {{"path", path.string()}});
    return std::unexpected(store.error());
  }
  (*store)->set_install_id(install_id);
  if (!exists || file->empty()) {
    // Write the fresh store so the DEK and file exist together from now on.
    if (auto r = (*store)->flush(); !r) {
      return std::unexpected(r.error());
    }
  }
  log::info("store_opened", {{"path", path.string()},
                             {"creds", std::to_string((*store)->size())},
                             {"keychain", keychain.name()}});
  return store;
}

}  // namespace swpk::store
