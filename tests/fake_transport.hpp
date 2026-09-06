#pragma once

#include "swpasskey/ctap/hid_defs.hpp"
#include "swpasskey/hid/transport.hpp"

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace swpk::test {

// In-memory Transport: the test plays the host. `host_write` feeds reports
// to the daemon; `host_read` collects what the daemon wrote.
class FakeTransport final : public hid::Transport {
public:
  Result<void> open() override { return {}; }
  void close() noexcept override {}

  Result<std::optional<hid::Report>> read(std::chrono::milliseconds timeout) override {
    std::unique_lock<std::mutex> lk(mu_);
    if (!cv_.wait_for(lk, timeout, [&] { return !to_device_.empty(); })) {
      return std::optional<hid::Report>{};
    }
    auto r = to_device_.front();
    to_device_.pop_front();
    return std::optional<hid::Report>{r};
  }

  Result<void> write(std::span<const std::uint8_t, hid::kReportSize> report) override {
    std::lock_guard<std::mutex> lk(mu_);
    hid::Report r{};
    std::memcpy(r.data(), report.data(), report.size());
    to_host_.push_back(r);
    host_cv_.notify_all();
    return {};
  }

  // --- host side ---
  void host_write(const hid::Report& r) {
    std::lock_guard<std::mutex> lk(mu_);
    to_device_.push_back(r);
    cv_.notify_one();
  }

  std::optional<hid::Report> host_read(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mu_);
    if (!host_cv_.wait_for(lk, timeout, [&] { return !to_host_.empty(); })) {
      return std::nullopt;
    }
    auto r = to_host_.front();
    to_host_.pop_front();
    return r;
  }

  std::vector<hid::Report> host_drain() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<hid::Report> out(to_host_.begin(), to_host_.end());
    to_host_.clear();
    return out;
  }

private:
  std::mutex mu_;
  std::condition_variable cv_;
  std::condition_variable host_cv_;
  std::deque<hid::Report> to_device_;
  std::deque<hid::Report> to_host_;
};

// --- packet helpers ---------------------------------------------------------
inline std::uint32_t cid_of(const hid::Report& r) {
  return static_cast<std::uint32_t>(r[0]) | (static_cast<std::uint32_t>(r[1]) << 8) |
         (static_cast<std::uint32_t>(r[2]) << 16) | (static_cast<std::uint32_t>(r[3]) << 24);
}

inline std::uint8_t cmd_of(const hid::Report& r) { return static_cast<std::uint8_t>(r[4] & 0x7F); }
inline bool is_init(const hid::Report& r) { return (r[4] & 0x80) != 0; }
inline std::uint16_t bcnt_of(const hid::Report& r) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(r[5]) << 8) | r[6]);
}

inline std::vector<hid::Report> make_frames(std::uint32_t cid, std::uint8_t cmd,
                                            std::span<const std::uint8_t> payload) {
  std::vector<hid::Report> out;
  hid::Report p{};
  p[0] = static_cast<std::uint8_t>(cid);
  p[1] = static_cast<std::uint8_t>(cid >> 8);
  p[2] = static_cast<std::uint8_t>(cid >> 16);
  p[3] = static_cast<std::uint8_t>(cid >> 24);
  p[4] = static_cast<std::uint8_t>(0x80 | cmd);
  p[5] = static_cast<std::uint8_t>(payload.size() >> 8);
  p[6] = static_cast<std::uint8_t>(payload.size());
  std::size_t n = payload.size() < 57 ? payload.size() : 57;
  if (n > 0) {
    std::memcpy(p.data() + 7, payload.data(), n);
  }
  out.push_back(p);
  std::size_t off = n;
  std::uint8_t seq = 0;
  while (off < payload.size()) {
    hid::Report c{};
    std::memcpy(c.data(), p.data(), 4);
    c[4] = seq++;
    const std::size_t m = (payload.size() - off) < 59 ? (payload.size() - off) : 59;
    std::memcpy(c.data() + 5, payload.data() + off, m);
    out.push_back(c);
    off += m;
  }
  return out;
}

// Reassembles a device->host message starting at `first` (an INIT packet),
// pulling CONT packets from `next()`.
template <class Next>
std::vector<std::uint8_t> reassemble(const hid::Report& first, Next&& next) {
  const std::size_t total = bcnt_of(first);
  std::vector<std::uint8_t> out(first.begin() + 7, first.begin() + 7 + (total < 57 ? total : 57));
  while (out.size() < total) {
    hid::Report c = next();
    const std::size_t m = (total - out.size()) < 59 ? (total - out.size()) : 59;
    out.insert(out.end(), c.begin() + 5, c.begin() + 5 + static_cast<std::ptrdiff_t>(m));
  }
  return out;
}

}  // namespace swpk::test
