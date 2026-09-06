#pragma once

#include "swpasskey/ctap/hid_defs.hpp"

#include <atomic>
#include <cstdint>

namespace swpk::ctap {

// Per-transaction state shared between the HID I/O thread and the
// authenticator worker. The HID thread sets `cancelled` on CTAPHID_CANCEL;
// the worker publishes the keepalive status it wants the HID thread to send.
struct CancelToken {
  std::atomic<bool> cancelled{false};
  std::atomic<std::uint8_t> keepalive{kKeepaliveProcessing};

  void cancel() noexcept { cancelled.store(true, std::memory_order_release); }
  bool is_cancelled() const noexcept { return cancelled.load(std::memory_order_acquire); }
  void set_up_needed(bool up) noexcept {
    keepalive.store(up ? kKeepaliveUpNeeded : kKeepaliveProcessing, std::memory_order_release);
  }
  std::uint8_t keepalive_status() const noexcept {
    return keepalive.load(std::memory_order_acquire);
  }
  void reset() noexcept {
    cancelled.store(false, std::memory_order_release);
    keepalive.store(kKeepaliveProcessing, std::memory_order_release);
  }
};

}  // namespace swpk::ctap
