// Development transport: 64-byte CTAPHID reports over a Unix domain socket.
// Lets python-fido2 / a test client drive the real daemon loop without
// /dev/uhid or an IOHIDUserDevice entitlement. Not a v1 user-facing feature.
#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace swpk::hid {
namespace {

class SocketTransport final : public Transport {
public:
  explicit SocketTransport(std::string path) : path_(std::move(path)) {}
  ~SocketTransport() override { close(); }

  Result<void> open() override {
    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
      return std::unexpected(Status::Other);
    }
    ::fcntl(listen_fd_, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(addr.sun_path)) {
      return std::unexpected(Status::InvalidParameter);
    }
    std::strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
    ::unlink(path_.c_str());
    const mode_t old = ::umask(0177);
    const int brc = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::umask(old);
    if (brc != 0 || ::listen(listen_fd_, 1) != 0) {
      log::error("hid_socket_bind_failed", {{"path", path_}, {"errno", std::strerror(errno)}});
      close();
      return std::unexpected(Status::Other);
    }
    log::warn("hid_socket_transport", {{"path", path_}, {"note", "development transport, not a HID device"}});
    return {};
  }

  void close() noexcept override {
    if (client_fd_ >= 0) {
      ::close(client_fd_);
      client_fd_ = -1;
    }
    if (listen_fd_ >= 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
      ::unlink(path_.c_str());
    }
  }

  Result<std::optional<Report>> read(std::chrono::milliseconds timeout) override {
    if (listen_fd_ < 0) {
      return std::unexpected(Status::Other);
    }
    pollfd pfds[2];
    pfds[0] = {listen_fd_, POLLIN, 0};
    pfds[1] = {client_fd_, POLLIN, 0};
    const nfds_t n = client_fd_ >= 0 ? 2 : 1;
    const int rc = ::poll(pfds, n, static_cast<int>(timeout.count()));
    if (rc == 0) {
      return std::optional<Report>{};
    }
    if (rc < 0) {
      return errno == EINTR ? Result<std::optional<Report>>{std::optional<Report>{}}
                            : std::unexpected(Status::Other);
    }
    if (pfds[0].revents & POLLIN) {
      const int c = ::accept(listen_fd_, nullptr, nullptr);
      if (c >= 0) {
        ::fcntl(c, F_SETFD, FD_CLOEXEC);
        if (client_fd_ >= 0) {
          ::close(client_fd_);
        }
        client_fd_ = c;
        log::debug("hid_socket_client_connected");
      }
      return std::optional<Report>{};
    }
    if (n == 2 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
      Report r{};
      std::size_t got = 0;
      while (got < kReportSize) {
        const ssize_t k = ::read(client_fd_, r.data() + got, kReportSize - got);
        if (k <= 0) {
          if (k < 0 && errno == EINTR) {
            continue;
          }
          ::close(client_fd_);
          client_fd_ = -1;
          log::debug("hid_socket_client_gone");
          return std::optional<Report>{};
        }
        got += static_cast<std::size_t>(k);
      }
      return std::optional<Report>{r};
    }
    return std::optional<Report>{};
  }

  Result<void> write(std::span<const std::uint8_t, kReportSize> report) override {
    if (client_fd_ < 0) {
      return {};  // no host attached: drop, like an unplugged interrupt endpoint
    }
    std::size_t off = 0;
    while (off < report.size()) {
      const ssize_t k = ::write(client_fd_, report.data() + off, report.size() - off);
      if (k <= 0) {
        if (k < 0 && errno == EINTR) {
          continue;
        }
        ::close(client_fd_);
        client_fd_ = -1;
        return {};
      }
      off += static_cast<std::size_t>(k);
    }
    return {};
  }

  std::string describe() const override { return "unix:" + path_; }

private:
  std::string path_;
  int listen_fd_{-1};
  int client_fd_{-1};
};

}  // namespace

std::unique_ptr<Transport> make_socket_transport(std::string path) {
  return std::make_unique<SocketTransport>(std::move(path));
}

}  // namespace swpk::hid
