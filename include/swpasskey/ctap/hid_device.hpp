#pragma once

#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/hid_defs.hpp"
#include "swpasskey/ctap/hid_framer.hpp"
#include "swpasskey/hid/transport.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace swpk::ctap {

// Transport-agnostic CTAPHID device logic: CID allocation (max 4, LRU
// reaping), INIT / PING / WINK / CANCEL / ERROR handling, and the decision
// of what to hand to the authenticator worker. No threads, no I/O: the
// daemon loop feeds it reports and writes whatever it returns.
class HidDevice {
public:
  using Clock = std::chrono::steady_clock;

  struct Ingest {
    std::vector<hid::Report> reply;      // write immediately, in order
    std::optional<Message> to_worker;    // CBOR / MSG for the worker
    bool cancel_inflight{false};         // CANCEL (or INIT resync) on the busy CID
  };

  struct Counters {
    std::uint64_t hid_init{0};
    std::uint64_t hid_error{0};
    std::uint64_t hid_ping{0};
  };
  struct AtomicCounters {
    std::atomic<std::uint64_t> hid_init{0};
    std::atomic<std::uint64_t> hid_error{0};
    std::atomic<std::uint64_t> hid_ping{0};
  };

  HidDevice(crypto::Provider& rng, std::uint8_t caps, bool msg_supported);

  // `inflight` is the CID currently owned by the worker (nullopt if idle).
  Ingest ingest(const hid::Report& report, std::optional<std::uint32_t> inflight,
                Clock::time_point now = Clock::now());

  // Emits ERR_MSG_TIMEOUT if a partial message has been idle for 500 ms.
  std::optional<hid::Report> poll_timeout(Clock::time_point now = Clock::now());

  std::vector<hid::Report> frame(const Message& msg) const { return framer_.frame(msg); }
  static hid::Report error_packet(std::uint32_t cid, HidErr err);
  static hid::Report keepalive_packet(std::uint32_t cid, std::uint8_t status);

  bool is_allocated(std::uint32_t cid) const;
  bool assembling() const { return framer_.assembling_cid().has_value(); }
  std::size_t allocated_count() const { return channels_.size(); }
  // Safe to call from any thread (stats socket).
  Counters counters() const {
    return Counters{counters_.hid_init.load(), counters_.hid_error.load(),
                    counters_.hid_ping.load()};
  }
  std::uint8_t caps() const { return caps_; }

private:
  struct Channel {
    std::uint32_t cid{};
    Clock::time_point last_used;
  };

  std::uint32_t allocate_cid(Clock::time_point now);
  void touch(std::uint32_t cid, Clock::time_point now);
  hid::Report init_response(std::uint32_t reply_cid, std::span<const std::uint8_t> nonce,
                            std::uint32_t assigned_cid) const;

  crypto::Provider& rng_;
  std::uint8_t caps_;
  bool msg_supported_;
  HidFramer framer_;
  std::vector<Channel> channels_;
  std::optional<Clock::time_point> assembling_since_;
  AtomicCounters counters_;
};

}  // namespace swpk::ctap
