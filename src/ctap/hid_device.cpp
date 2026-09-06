#include "swpasskey/ctap/hid_device.hpp"

#include "swpasskey/constants.hpp"
#include "swpasskey/log/log.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace swpk::ctap {
namespace {

constexpr std::size_t kMaxChannels = 4;

std::uint32_t read_cid_le(const hid::Report& r) {
  return static_cast<std::uint32_t>(r[0]) | (static_cast<std::uint32_t>(r[1]) << 8) |
         (static_cast<std::uint32_t>(r[2]) << 16) | (static_cast<std::uint32_t>(r[3]) << 24);
}

void write_cid_le(hid::Report& r, std::uint32_t cid) {
  r[0] = static_cast<std::uint8_t>(cid);
  r[1] = static_cast<std::uint8_t>(cid >> 8);
  r[2] = static_cast<std::uint8_t>(cid >> 16);
  r[3] = static_cast<std::uint8_t>(cid >> 24);
}

std::string hex32(std::uint32_t v) {
  char buf[12];
  std::snprintf(buf, sizeof(buf), "%08x", v);
  return buf;
}

}  // namespace

HidDevice::HidDevice(crypto::Provider& rng, std::uint8_t caps, bool msg_supported)
    : rng_(rng), caps_(caps), msg_supported_(msg_supported) {}

hid::Report HidDevice::error_packet(std::uint32_t cid, HidErr err) {
  hid::Report r{};
  write_cid_le(r, cid);
  r[4] = static_cast<std::uint8_t>(kTypeInit | kCmdError);
  r[5] = 0;
  r[6] = 1;
  r[7] = static_cast<std::uint8_t>(err);
  return r;
}

hid::Report HidDevice::keepalive_packet(std::uint32_t cid, std::uint8_t status) {
  hid::Report r{};
  write_cid_le(r, cid);
  r[4] = static_cast<std::uint8_t>(kTypeInit | kCmdKeepalive);
  r[5] = 0;
  r[6] = 1;
  r[7] = status;
  return r;
}

bool HidDevice::is_allocated(std::uint32_t cid) const {
  return std::any_of(channels_.begin(), channels_.end(),
                     [cid](const Channel& c) { return c.cid == cid; });
}

void HidDevice::touch(std::uint32_t cid, Clock::time_point now) {
  for (auto& c : channels_) {
    if (c.cid == cid) {
      c.last_used = now;
      return;
    }
  }
}

std::uint32_t HidDevice::allocate_cid(Clock::time_point now) {
  if (channels_.size() >= kMaxChannels) {
    auto lru = std::min_element(channels_.begin(), channels_.end(),
                                [](const Channel& a, const Channel& b) {
                                  return a.last_used < b.last_used;
                                });
    log::debug("cid_reaped", {{"cid", hex32(lru->cid)}});
    channels_.erase(lru);
  }
  for (;;) {
    std::uint8_t raw[4];
    if (!rng_.random(raw)) {
      // RNG failure: fall back to a counter-derived CID; still never 0 / bcast.
      static std::uint32_t fallback = 0x10000001u;
      fallback += 0x9E3779B9u;
      raw[0] = static_cast<std::uint8_t>(fallback);
      raw[1] = static_cast<std::uint8_t>(fallback >> 8);
      raw[2] = static_cast<std::uint8_t>(fallback >> 16);
      raw[3] = static_cast<std::uint8_t>(fallback >> 24);
    }
    const std::uint32_t cid = static_cast<std::uint32_t>(raw[0]) |
                              (static_cast<std::uint32_t>(raw[1]) << 8) |
                              (static_cast<std::uint32_t>(raw[2]) << 16) |
                              (static_cast<std::uint32_t>(raw[3]) << 24);
    if (cid == 0 || cid == kBroadcastCid || is_allocated(cid)) {
      continue;
    }
    channels_.push_back(Channel{cid, now});
    return cid;
  }
}

hid::Report HidDevice::init_response(std::uint32_t reply_cid,
                                     std::span<const std::uint8_t> nonce,
                                     std::uint32_t assigned_cid) const {
  Message m;
  m.cid = reply_cid;
  m.cmd = kCmdInit;
  m.payload.assign(nonce.begin(), nonce.end());
  m.payload.push_back(static_cast<std::uint8_t>(assigned_cid));
  m.payload.push_back(static_cast<std::uint8_t>(assigned_cid >> 8));
  m.payload.push_back(static_cast<std::uint8_t>(assigned_cid >> 16));
  m.payload.push_back(static_cast<std::uint8_t>(assigned_cid >> 24));
  m.payload.push_back(kHidVersion);
  m.payload.push_back(0);  // major
  m.payload.push_back(1);  // minor
  m.payload.push_back(0);  // build
  m.payload.push_back(caps_);
  return framer_.frame(m).front();
}

std::optional<hid::Report> HidDevice::poll_timeout(Clock::time_point now) {
  const auto cid = framer_.assembling_cid();
  if (!cid || !assembling_since_) {
    return std::nullopt;
  }
  if (now - *assembling_since_ < kInterPacketTimeout) {
    return std::nullopt;
  }
  assembling_since_.reset();
  (void)framer_.on_timeout();
  ++counters_.hid_error;
  log::debug("hid_msg_timeout", {{"cid", hex32(*cid)}});
  return error_packet(*cid, HidErr::MsgTimeout);
}

HidDevice::Ingest HidDevice::ingest(const hid::Report& report,
                                    std::optional<std::uint32_t> inflight,
                                    Clock::time_point now) {
  Ingest out;
  const std::uint32_t cid = read_cid_le(report);

  auto fail = [&](std::uint32_t err_cid, HidErr err) {
    ++counters_.hid_error;
    log::debug("hid_error", {{"cid", hex32(err_cid)},
                             {"err", std::to_string(static_cast<int>(err))}});
    out.reply.push_back(error_packet(err_cid, err));
    return out;
  };

  // Broadcast INIT is always answered, even mid-assembly on another CID.
  if (cid == kBroadcastCid && report[4] == (kTypeInit | kCmdInit)) {
    const std::uint16_t bcnt =
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(report[5]) << 8) | report[6]);
    if (bcnt != 8) {
      return fail(cid, HidErr::InvalidLen);
    }
    ++counters_.hid_init;
    const std::uint32_t assigned = allocate_cid(now);
    log::debug("hid_init", {{"cid", hex32(assigned)}});
    out.reply.push_back(init_response(kBroadcastCid, std::span<const std::uint8_t>(report).subspan(7, 8), assigned));
    return out;
  }

  auto r = framer_.ingest(report);
  if (!r) {
    return fail(cid, r.error());
  }
  if (!r->has_value()) {
    // Partial message; (re)arm the inter-packet timer.
    assembling_since_ = now;
    return out;
  }
  assembling_since_.reset();
  Message msg = std::move(**r);

  if (msg.cmd == kCmdInit) {
    if (msg.payload.size() != 8) {
      return fail(cid, HidErr::InvalidLen);
    }
    ++counters_.hid_init;
    if (!is_allocated(cid)) {
      return fail(cid, HidErr::InvalidChannel);
    }
    // Resync on an existing channel: abort anything in flight on it.
    touch(cid, now);
    if (inflight && *inflight == cid) {
      out.cancel_inflight = true;
    }
    out.reply.push_back(init_response(cid, msg.payload, cid));
    return out;
  }

  if (cid == kBroadcastCid || !is_allocated(cid)) {
    return fail(cid, HidErr::InvalidChannel);
  }
  touch(cid, now);

  switch (msg.cmd) {
    case kCmdPing: {
      ++counters_.hid_ping;
      out.reply = framer_.frame(msg);
      return out;
    }
    case kCmdWink: {
      Message w{cid, kCmdWink, {}};
      out.reply = framer_.frame(w);
      return out;
    }
    case kCmdCancel: {
      if (inflight && *inflight == cid) {
        out.cancel_inflight = true;
        log::debug("hid_cancel", {{"cid", hex32(cid)}});
      }
      return out;
    }
    case kCmdMsg:
      if (!msg_supported_) {
        return fail(cid, HidErr::InvalidCmd);
      }
      [[fallthrough]];
    case kCmdCbor: {
      if (inflight) {
        return fail(cid, HidErr::ChannelBusy);
      }
      out.to_worker = std::move(msg);
      return out;
    }
    case kCmdLock:
    default:
      return fail(cid, HidErr::InvalidCmd);
  }
}

}  // namespace swpk::ctap
