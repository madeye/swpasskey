#pragma once

#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/cancel_token.hpp"
#include "swpasskey/ctap/hid_device.hpp"
#include "swpasskey/ctap/request_handler.hpp"
#include "swpasskey/hid/transport.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace swpk::daemon {

// The real I/O loop (DESIGN.md "Daemon I/O"). `run()` is the HID I/O thread:
// it owns the Transport, ingests reports, answers INIT/PING/WINK/ERROR
// itself, hands CBOR/MSG to a single worker thread, and pumps
// CTAPHID_KEEPALIVE every 100 ms on the in-flight CID. The worker never
// touches the Transport; it posts framed reports to an outbox.
class Loop {
public:
  struct Stats {
    std::uint64_t cbor_ok{0};
    std::uint64_t cbor_err{0};
    std::uint64_t keepalives{0};
    std::uint64_t cancels{0};
  };

  Loop(hid::Transport& transport, ctap::RequestHandler& handler, crypto::Provider& rng);
  ~Loop();
  Loop(const Loop&) = delete;
  Loop& operator=(const Loop&) = delete;

  // Blocks the calling thread (the HID I/O thread) until stop() is called or
  // the transport fails. Returns false on transport failure.
  bool run();
  void stop();

  Stats stats() const;
  const ctap::HidDevice& device() const { return device_; }

private:
  struct Inflight {
    std::optional<ctap::Message> cmd;
    std::uint32_t cid{};
    ctap::CancelToken token;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point last_keepalive;
  };

  void worker_main();
  bool write_all(std::vector<hid::Report> reports);

  hid::Transport& transport_;
  ctap::RequestHandler& handler_;
  ctap::HidDevice device_;

  std::atomic<bool> stop_{false};
  mutable std::mutex mu_;
  std::condition_variable worker_cv_;
  Inflight inflight_;
  std::vector<hid::Report> outbox_;
  Stats stats_;
  std::thread worker_;
};

}  // namespace swpk::daemon
