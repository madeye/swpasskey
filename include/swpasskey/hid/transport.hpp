#pragma once

#include "swpasskey/hid/report_descriptor.hpp"
#include "swpasskey/status.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace swpk::hid {

using Report = std::array<std::uint8_t, kReportSize>;

struct DeviceConfig {
  std::uint16_t vid{0x1209};
  std::uint16_t pid{0xF1D0};
  std::uint16_t version{0x0001};
  std::string manufacturer{"swpasskey"};
  std::string product{"swpasskey Software Authenticator"};
  std::string serial;  // 16 hex chars from the serial sidecar
};

// A virtual HID device. `read` is the only entry point that blocks; it is
// called from the HID I/O thread alone. `write` may only be called from that
// same thread. Implementations must never invoke CTAP code.
class Transport {
public:
  virtual ~Transport() = default;
  virtual Result<void> open() = 0;
  virtual void close() noexcept = 0;
  // Blocks until a host->device report arrives or `timeout` elapses.
  // nullopt = timeout (no report). Error = device gone.
  virtual Result<std::optional<Report>> read(std::chrono::milliseconds timeout) = 0;
  // device->host report.
  virtual Result<void> write(std::span<const std::uint8_t, kReportSize> report) = 0;
  // Human-readable node name for logs ("/dev/hidraw3", "IOHIDUserDevice"), may be empty.
  virtual std::string describe() const { return {}; }
};

// Platform transport: UHID on Linux, IOHIDUserDevice on macOS. Returns
// nullptr on unsupported platforms.
std::unique_ptr<Transport> make_transport(DeviceConfig cfg);

}  // namespace swpk::hid
