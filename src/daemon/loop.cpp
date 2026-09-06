#include "swpasskey/daemon/loop.hpp"

#include "swpasskey/log/log.hpp"

#include <chrono>
#include <cstdio>
#include <string>

namespace swpk::daemon {
namespace {

using Clock = std::chrono::steady_clock;

// Read timeouts: tight while a transaction is in flight (keepalive + response
// latency), relaxed while assembling (500 ms inter-packet timer), long when idle.
constexpr auto kBusyPoll = std::chrono::milliseconds(5);
constexpr auto kAssemblingPoll = std::chrono::milliseconds(50);
constexpr auto kIdlePoll = std::chrono::milliseconds(250);

std::string hex32(std::uint32_t v) {
  char buf[12];
  std::snprintf(buf, sizeof(buf), "%08x", v);
  return buf;
}

}  // namespace

Loop::Loop(hid::Transport& transport, ctap::RequestHandler& handler, crypto::Provider& rng)
    : transport_(transport),
      handler_(handler),
      device_(rng, static_cast<std::uint8_t>(handler.supports_u2f()
                                                 ? (ctap::kCapCbor | ctap::kCapWink)
                                                 : (ctap::kCapCbor | ctap::kCapNmsg)),
              handler.supports_u2f()) {}

Loop::~Loop() {
  stop();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void Loop::stop() {
  stop_.store(true);
  std::lock_guard<std::mutex> lk(mu_);
  inflight_.token.cancel();
  worker_cv_.notify_all();
}

Loop::Stats Loop::stats() const {
  std::lock_guard<std::mutex> lk(mu_);
  return stats_;
}

bool Loop::write_all(std::vector<hid::Report> reports) {
  for (const auto& r : reports) {
    if (!transport_.write(r)) {
      log::error("hid_write_failed");
      return false;
    }
  }
  return true;
}

void Loop::worker_main() {
  for (;;) {
    ctap::Message msg;
    {
      std::unique_lock<std::mutex> lk(mu_);
      worker_cv_.wait(lk, [&] { return stop_.load() || inflight_.cmd.has_value(); });
      if (stop_.load()) {
        return;
      }
      msg = *inflight_.cmd;  // keep the slot occupied while we work
    }

    const auto t0 = Clock::now();
    ctap::Message resp;
    resp.cid = msg.cid;
    resp.cmd = msg.cmd;
    bool ok = true;
    if (msg.cmd == ctap::kCmdCbor) {
      auto r = handler_.handle_cbor(msg.payload, inflight_.token);
      if (r) {
        resp.payload.reserve(r->size() + 1);
        resp.payload.push_back(0x00);
        resp.payload.insert(resp.payload.end(), r->begin(), r->end());
      } else {
        ok = false;
        resp.payload.push_back(static_cast<std::uint8_t>(r.error()));
      }
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);
      log::debug("cbor_done", {{"cid", hex32(msg.cid)},
                               {"status", std::to_string(resp.payload[0])},
                               {"ms", std::to_string(ms.count())}});
    } else {
      resp.payload = handler_.handle_u2f(msg.payload, inflight_.token);
    }

    auto frames = device_.frame(resp);
    {
      // Publish the response and release the slot atomically so the HID thread
      // never writes a keepalive after the response INIT packet.
      std::lock_guard<std::mutex> lk(mu_);
      outbox_.insert(outbox_.end(), frames.begin(), frames.end());
      inflight_.cmd.reset();
      inflight_.token.reset();
      if (ok) {
        ++stats_.cbor_ok;
      } else {
        ++stats_.cbor_err;
      }
    }
  }
}

bool Loop::run() {
  worker_ = std::thread([this] { worker_main(); });

  bool healthy = true;
  while (!stop_.load()) {
    // 1. Drain outbox and decide whether a keepalive is due.
    std::vector<hid::Report> to_write;
    std::optional<std::uint32_t> busy_cid;
    {
      std::lock_guard<std::mutex> lk(mu_);
      to_write.swap(outbox_);
      if (inflight_.cmd) {
        busy_cid = inflight_.cid;
        const auto now = Clock::now();
        if (now - inflight_.last_keepalive >= ctap::kKeepaliveInterval) {
          inflight_.last_keepalive = now;
          to_write.push_back(ctap::HidDevice::keepalive_packet(
              inflight_.cid, inflight_.token.keepalive_status()));
          ++stats_.keepalives;
        }
      }
    }
    if (!write_all(std::move(to_write))) {
      healthy = false;
      break;
    }

    // 2. Inter-packet timeout on a partial assembly.
    if (auto t = device_.poll_timeout()) {
      if (!write_all({*t})) {
        healthy = false;
        break;
      }
    }

    // 3. Read with a bounded wait.
    const auto timeout = busy_cid                ? kBusyPoll
                         : device_.assembling()  ? kAssemblingPoll
                                                 : kIdlePoll;
    auto rd = transport_.read(timeout);
    if (!rd) {
      log::error("hid_read_failed");
      healthy = false;
      break;
    }
    if (!rd->has_value()) {
      continue;
    }

    // 4. Ingest under the lock so the busy/idle decision cannot race with a
    //    worker completion. ingest() never blocks or does I/O.
    std::vector<hid::Report> replies;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::optional<std::uint32_t> now_busy =
          inflight_.cmd ? std::optional<std::uint32_t>{inflight_.cid} : std::nullopt;
      auto ing = device_.ingest(**rd, now_busy);
      replies = std::move(ing.reply);
      if (ing.cancel_inflight && inflight_.cmd) {
        inflight_.token.cancel();
        ++stats_.cancels;
      }
      if (ing.to_worker) {
        inflight_.cid = ing.to_worker->cid;
        inflight_.token.reset();
        inflight_.started = Clock::now();
        inflight_.last_keepalive = inflight_.started;
        inflight_.cmd = std::move(ing.to_worker);
        worker_cv_.notify_one();
      }
    }
    if (!write_all(std::move(replies))) {
      healthy = false;
      break;
    }
  }

  stop();
  if (worker_.joinable()) {
    worker_.join();
  }
  return healthy;
}

}  // namespace swpk::daemon
