// macOS IOHIDUserDevice transport. Requires the restricted entitlement
// com.apple.developer.hid.virtual.device (signed .app + provisioning profile).
#if defined(__APPLE__)

#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDKeys.h>
#import <IOKit/hidsystem/IOHIDUserDevice.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>

namespace swpk::hid {
namespace {

constexpr std::size_t kQueueDepth = 32;

class IokitTransport final : public Transport {
public:
  explicit IokitTransport(DeviceConfig cfg) : cfg_(std::move(cfg)) {}
  ~IokitTransport() override { close(); }

  Result<void> open() override {
    @autoreleasepool {
      NSDictionary* props = @{
        @(kIOHIDReportDescriptorKey) :
            [NSData dataWithBytes:kReportDescriptor length:sizeof(kReportDescriptor)],
        @(kIOHIDVendorIDKey) : @(cfg_.vid),
        @(kIOHIDProductIDKey) : @(cfg_.pid),
        @(kIOHIDVersionNumberKey) : @(cfg_.version),
        @(kIOHIDManufacturerKey) : [NSString stringWithUTF8String:cfg_.manufacturer.c_str()],
        @(kIOHIDProductKey) : [NSString stringWithUTF8String:cfg_.product.c_str()],
        @(kIOHIDSerialNumberKey) : [NSString stringWithUTF8String:cfg_.serial.c_str()],
        @(kIOHIDTransportKey) : @"USB",
        @(kIOHIDPrimaryUsagePageKey) : @(kUsagePage),
        @(kIOHIDPrimaryUsageKey) : @(kUsageCtapHid),
        @(kIOHIDMaxInputReportSizeKey) : @(kReportSize),
        @(kIOHIDMaxOutputReportSizeKey) : @(kReportSize),
      };
      queue_ = dispatch_queue_create("com.tangzixiang.swpasskey.iohid", DISPATCH_QUEUE_SERIAL);
      device_ = IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault,
                                                    (__bridge CFDictionaryRef)props, 0);
      if (device_ == nullptr) {
        log::error("iohid_create_failed",
                   {{"hint", "requires com.apple.developer.hid.virtual.device entitlement "
                             "(signed .app + provisioning profile)"}});
        return std::unexpected(Status::Other);
      }
      IokitTransport* self = this;
      IOHIDUserDeviceRegisterSetReportBlock(
          device_, ^IOReturn(IOHIDReportType type, uint32_t /*reportID*/, const uint8_t* report,
                             CFIndex len) {
            if (type != kIOHIDReportTypeOutput || report == nullptr || len <= 0) {
              return kIOReturnSuccess;
            }
            self->on_set_report(std::span<const std::uint8_t>(
                report, static_cast<std::size_t>(len)));
            return kIOReturnSuccess;
          });
      IOHIDUserDeviceRegisterGetReportBlock(
          device_, ^IOReturn(IOHIDReportType /*type*/, uint32_t /*reportID*/, uint8_t* report,
                             CFIndex* len) {
            if (report == nullptr || len == nullptr) {
              return kIOReturnBadArgument;
            }
            const CFIndex n = *len < static_cast<CFIndex>(kReportSize)
                                  ? *len
                                  : static_cast<CFIndex>(kReportSize);
            std::memset(report, 0, static_cast<std::size_t>(n));
            *len = n;
            return kIOReturnSuccess;
          });
      IOHIDUserDeviceSetDispatchQueue(device_, queue_);
      IOHIDUserDeviceSetCancelHandler(device_, ^{
        self->on_cancelled();
      });
      IOHIDUserDeviceActivate(device_);
      active_ = true;
      log::info("iohid_created", {{"product", cfg_.product}, {"serial", cfg_.serial}});
      return {};
    }
  }

  void close() noexcept override {
    if (device_ != nullptr) {
      if (active_) {
        std::unique_lock<std::mutex> lk(mu_);
        cancelled_ = false;
        lk.unlock();
        IOHIDUserDeviceCancel(device_);
        lk.lock();
        cancel_cv_.wait_for(lk, std::chrono::seconds(2), [&] { return cancelled_; });
        active_ = false;
      }
      CFRelease(device_);
      device_ = nullptr;
    }
    queue_ = nullptr;  // ARC-managed dispatch object
  }

  Result<std::optional<Report>> read(std::chrono::milliseconds timeout) override {
    if (device_ == nullptr) {
      return std::unexpected(Status::Other);
    }
    std::unique_lock<std::mutex> lk(mu_);
    if (!cv_.wait_for(lk, timeout, [&] { return !inbox_.empty(); })) {
      return std::optional<Report>{};
    }
    Report r = inbox_.front();
    inbox_.pop_front();
    return std::optional<Report>{r};
  }

  Result<void> write(std::span<const std::uint8_t, kReportSize> report) override {
    if (device_ == nullptr) {
      return std::unexpected(Status::Other);
    }
    const IOReturn rc = IOHIDUserDeviceHandleReportWithTimeStamp(
        device_, mach_absolute_time(), report.data(), static_cast<CFIndex>(report.size()));
    if (rc != kIOReturnSuccess) {
      log::error("iohid_handle_report_failed", {{"rc", std::to_string(rc)}});
      return std::unexpected(Status::Other);
    }
    return {};
  }

  std::string describe() const override { return "IOHIDUserDevice"; }

private:
  void on_set_report(std::span<const std::uint8_t> data) {
    Report r{};
    if (data.size() > kReportSize && data[0] == 0) {
      data = data.subspan(1);
    }
    const std::size_t n = data.size() < kReportSize ? data.size() : kReportSize;
    std::memcpy(r.data(), data.data(), n);
    std::lock_guard<std::mutex> lk(mu_);
    if (inbox_.size() >= kQueueDepth) {
      inbox_.pop_front();
      log::warn("iohid_inbox_overflow");
    }
    inbox_.push_back(r);
    cv_.notify_one();
  }

  void on_cancelled() {
    std::lock_guard<std::mutex> lk(mu_);
    cancelled_ = true;
    cancel_cv_.notify_all();
  }

  DeviceConfig cfg_;
  IOHIDUserDeviceRef device_{nullptr};
  dispatch_queue_t queue_{nullptr};
  bool active_{false};
  std::mutex mu_;
  std::condition_variable cv_;
  std::condition_variable cancel_cv_;
  bool cancelled_{false};
  std::deque<Report> inbox_;
};

}  // namespace

std::unique_ptr<Transport> make_transport(DeviceConfig cfg) {
  return std::make_unique<IokitTransport>(std::move(cfg));
}

}  // namespace swpk::hid

#endif  // __APPLE__
