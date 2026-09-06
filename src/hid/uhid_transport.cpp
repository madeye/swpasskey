// Linux UHID transport: /dev/uhid -> /dev/hidrawN virtual FIDO device.
#if defined(__linux__)

#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <linux/input.h>
#include <linux/uhid.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace swpk::hid {
namespace {

constexpr const char* kUhidPath = "/dev/uhid";

class UhidTransport final : public Transport {
public:
  explicit UhidTransport(DeviceConfig cfg) : cfg_(std::move(cfg)) {}
  ~UhidTransport() override { close(); }

  Result<void> open() override {
    fd_ = ::open(kUhidPath, O_RDWR | O_CLOEXEC);
    if (fd_ < 0) {
      log::error("uhid_open_failed", {{"path", kUhidPath}, {"errno", std::strerror(errno)}});
      return std::unexpected(Status::Other);
    }
    uhid_event ev{};
    ev.type = UHID_CREATE2;
    auto& c = ev.u.create2;
    std::strncpy(reinterpret_cast<char*>(c.name), cfg_.product.c_str(), sizeof(c.name) - 1);
    std::strncpy(reinterpret_cast<char*>(c.phys), "swpasskey", sizeof(c.phys) - 1);
    std::strncpy(reinterpret_cast<char*>(c.uniq), cfg_.serial.c_str(), sizeof(c.uniq) - 1);
    c.rd_size = static_cast<__u16>(sizeof(kReportDescriptor));
    std::memcpy(c.rd_data, kReportDescriptor, sizeof(kReportDescriptor));
    c.bus = BUS_USB;
    c.vendor = cfg_.vid;
    c.product = cfg_.pid;
    c.version = cfg_.version;
    c.country = 0;
    if (!write_event(ev)) {
      log::error("uhid_create2_failed", {{"errno", std::strerror(errno)}});
      close();
      return std::unexpected(Status::Other);
    }
    log::info("uhid_created", {{"name", cfg_.product}, {"serial", cfg_.serial}});
    return {};
  }

  void close() noexcept override {
    if (fd_ >= 0) {
      uhid_event ev{};
      ev.type = UHID_DESTROY;
      (void)write_event(ev);
      ::close(fd_);
      fd_ = -1;
    }
  }

  Result<std::optional<Report>> read(std::chrono::milliseconds timeout) override {
    if (fd_ < 0) {
      return std::unexpected(Status::Other);
    }
    for (;;) {
      pollfd pfd{fd_, POLLIN, 0};
      const int rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
      if (rc == 0) {
        return std::optional<Report>{};
      }
      if (rc < 0) {
        if (errno == EINTR) {
          continue;
        }
        return std::unexpected(Status::Other);
      }
      uhid_event ev{};
      const ssize_t n = ::read(fd_, &ev, sizeof(ev));
      if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) {
          continue;
        }
        log::error("uhid_read_failed", {{"errno", std::strerror(errno)}});
        return std::unexpected(Status::Other);
      }
      if (static_cast<std::size_t>(n) < sizeof(ev.type)) {
        continue;
      }
      switch (ev.type) {
        case UHID_START:
          log::debug("uhid_start");
          break;
        case UHID_STOP:
          log::debug("uhid_stop");
          break;
        case UHID_OPEN:
          log::debug("uhid_open");
          break;
        case UHID_CLOSE:
          log::debug("uhid_close");
          break;
        case UHID_OUTPUT: {
          const auto& o = ev.u.output;
          if (o.rtype != UHID_OUTPUT_REPORT) {
            break;
          }
          return to_report(std::span<const std::uint8_t>(o.data, o.size));
        }
        case UHID_SET_REPORT: {
          const auto& s = ev.u.set_report;
          uhid_event reply{};
          reply.type = UHID_SET_REPORT_REPLY;
          reply.u.set_report_reply.id = s.id;
          reply.u.set_report_reply.err = 0;
          (void)write_event(reply);
          if (s.rtype == UHID_OUTPUT_REPORT) {
            return to_report(std::span<const std::uint8_t>(s.data, s.size));
          }
          break;
        }
        case UHID_GET_REPORT: {
          // Zeroed 64-byte input report so the kernel does not stall.
          uhid_event reply{};
          reply.type = UHID_GET_REPORT_REPLY;
          reply.u.get_report_reply.id = ev.u.get_report.id;
          reply.u.get_report_reply.err = 0;
          reply.u.get_report_reply.size = kReportSize;
          (void)write_event(reply);
          break;
        }
        default:
          break;
      }
      // Non-report event: keep polling within the same call but with no
      // additional wait so callers see bounded latency.
      timeout = std::chrono::milliseconds(0);
    }
  }

  Result<void> write(std::span<const std::uint8_t, kReportSize> report) override {
    if (fd_ < 0) {
      return std::unexpected(Status::Other);
    }
    uhid_event ev{};
    ev.type = UHID_INPUT2;
    ev.u.input2.size = kReportSize;
    std::memcpy(ev.u.input2.data, report.data(), kReportSize);
    if (!write_event(ev)) {
      log::error("uhid_input2_failed", {{"errno", std::strerror(errno)}});
      return std::unexpected(Status::Other);
    }
    return {};
  }

  std::string describe() const override { return kUhidPath; }

private:
  static Report to_report(std::span<const std::uint8_t> data) {
    Report r{};
    // hidraw write() prepends the report number (0 for un-numbered reports),
    // so a 65-byte payload with a leading zero is the common shape.
    if (data.size() > kReportSize && data[0] == 0) {
      data = data.subspan(1);
    }
    const std::size_t n = data.size() < kReportSize ? data.size() : kReportSize;
    std::memcpy(r.data(), data.data(), n);
    return r;
  }

  bool write_event(const uhid_event& ev) const {
    for (;;) {
      const ssize_t n = ::write(fd_, &ev, sizeof(ev));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      return n == static_cast<ssize_t>(sizeof(ev));
    }
  }

  DeviceConfig cfg_;
  int fd_{-1};
};

}  // namespace

std::unique_ptr<Transport> make_transport(DeviceConfig cfg) {
  return std::make_unique<UhidTransport>(std::move(cfg));
}

}  // namespace swpk::hid

#endif  // __linux__
