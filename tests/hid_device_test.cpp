#include "swpasskey/ctap/hid_device.hpp"
#include "fake_transport.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace swpk;
using namespace swpk::test;

namespace {

struct Fx {
  crypto::Provider rng;
  ctap::HidDevice dev{rng, static_cast<std::uint8_t>(ctap::kCapCbor | ctap::kCapNmsg), false};

  std::uint32_t init() {
    const std::uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    auto pk = make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front();
    auto out = dev.ingest(pk, std::nullopt);
    REQUIRE(out.reply.size() == 1);
    const auto& r = out.reply[0];
    REQUIRE(cid_of(r) == ctap::kBroadcastCid);
    REQUIRE(cmd_of(r) == ctap::kCmdInit);
    REQUIRE(bcnt_of(r) == 17);
    REQUIRE(std::equal(nonce, nonce + 8, r.begin() + 7));
    const std::uint32_t cid = static_cast<std::uint32_t>(r[15]) | (static_cast<std::uint32_t>(r[16]) << 8) |
                              (static_cast<std::uint32_t>(r[17]) << 16) | (static_cast<std::uint32_t>(r[18]) << 24);
    REQUIRE(r[19] == ctap::kHidVersion);
    REQUIRE(r[23] == (ctap::kCapCbor | ctap::kCapNmsg));
    REQUIRE(cid != 0);
    REQUIRE(cid != ctap::kBroadcastCid);
    return cid;
  }
};

}  // namespace

TEST_CASE("INIT allocates a CID and echoes nonce/caps", "[hiddev]") {
  Fx f;
  auto a = f.init();
  auto b = f.init();
  REQUIRE(a != b);
  REQUIRE(f.dev.allocated_count() == 2);
  REQUIRE(f.dev.counters().hid_init == 2);
}

TEST_CASE("INIT with wrong nonce length is INVALID_LEN", "[hiddev]") {
  Fx f;
  const std::uint8_t nonce[4] = {1, 2, 3, 4};
  auto out = f.dev.ingest(make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front(), std::nullopt);
  REQUIRE(out.reply.size() == 1);
  REQUIRE(cmd_of(out.reply[0]) == ctap::kCmdError);
  REQUIRE(out.reply[0][7] == static_cast<std::uint8_t>(ctap::HidErr::InvalidLen));
}

TEST_CASE("fifth CID reaps the least recently used", "[hiddev]") {
  Fx f;
  auto c1 = f.init();
  auto c2 = f.init();
  auto c3 = f.init();
  auto c4 = f.init();
  // Touch c1 so c2 becomes LRU.
  const std::uint8_t ping[] = {0xAA};
  auto out = f.dev.ingest(make_frames(c1, ctap::kCmdPing, ping).front(), std::nullopt);
  REQUIRE(out.reply.size() == 1);
  auto c5 = f.init();
  REQUIRE(f.dev.allocated_count() == 4);
  REQUIRE(f.dev.is_allocated(c1));
  REQUIRE_FALSE(f.dev.is_allocated(c2));
  REQUIRE(f.dev.is_allocated(c3));
  REQUIRE(f.dev.is_allocated(c4));
  REQUIRE(f.dev.is_allocated(c5));
  // The reaped CID now gets INVALID_CHANNEL.
  auto e = f.dev.ingest(make_frames(c2, ctap::kCmdPing, ping).front(), std::nullopt);
  REQUIRE(cmd_of(e.reply[0]) == ctap::kCmdError);
  REQUIRE(e.reply[0][7] == static_cast<std::uint8_t>(ctap::HidErr::InvalidChannel));
}

TEST_CASE("PING echoes a multi-packet payload", "[hiddev]") {
  Fx f;
  auto cid = f.init();
  std::vector<std::uint8_t> payload(200);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i);
  auto frames = make_frames(cid, ctap::kCmdPing, payload);
  REQUIRE(frames.size() == 4);
  ctap::HidDevice::Ingest last;
  for (const auto& fr : frames) {
    last = f.dev.ingest(fr, std::nullopt);
  }
  REQUIRE(last.reply.size() == 4);
  std::size_t idx = 1;
  auto body = reassemble(last.reply[0], [&] { return last.reply[idx++]; });
  REQUIRE(body == payload);
}

TEST_CASE("CBOR goes to the worker; second CBOR while busy is CHANNEL_BUSY", "[hiddev]") {
  Fx f;
  auto c1 = f.init();
  auto c2 = f.init();
  const std::uint8_t gi[] = {0x04};
  auto a = f.dev.ingest(make_frames(c1, ctap::kCmdCbor, gi).front(), std::nullopt);
  REQUIRE(a.to_worker.has_value());
  REQUIRE(a.to_worker->cid == c1);
  REQUIRE(a.reply.empty());
  auto b = f.dev.ingest(make_frames(c2, ctap::kCmdCbor, gi).front(), c1);
  REQUIRE_FALSE(b.to_worker.has_value());
  REQUIRE(b.reply.size() == 1);
  REQUIRE(cid_of(b.reply[0]) == c2);
  REQUIRE(b.reply[0][7] == static_cast<std::uint8_t>(ctap::HidErr::ChannelBusy));
}

TEST_CASE("CANCEL on the in-flight CID sets cancel; other CID ignored", "[hiddev]") {
  Fx f;
  auto c1 = f.init();
  auto c2 = f.init();
  auto a = f.dev.ingest(make_frames(c2, ctap::kCmdCancel, {}).front(), c1);
  REQUIRE_FALSE(a.cancel_inflight);
  auto b = f.dev.ingest(make_frames(c1, ctap::kCmdCancel, {}).front(), c1);
  REQUIRE(b.cancel_inflight);
  REQUIRE(b.reply.empty());
}

TEST_CASE("broadcast INIT is answered mid-assembly on another CID", "[hiddev]") {
  Fx f;
  auto c1 = f.init();
  std::vector<std::uint8_t> payload(100, 0x11);
  auto frames = make_frames(c1, ctap::kCmdCbor, payload);
  auto p = f.dev.ingest(frames[0], std::nullopt);
  REQUIRE(p.reply.empty());
  REQUIRE(f.dev.assembling());
  auto c2 = f.init();  // must succeed even though c1 is mid-message
  REQUIRE(c2 != c1);
  auto q = f.dev.ingest(frames[1], std::nullopt);
  REQUIRE(q.to_worker.has_value());
}

TEST_CASE("MSG without U2F is INVALID_CMD; LOCK is INVALID_CMD", "[hiddev]") {
  Fx f;
  auto cid = f.init();
  const std::uint8_t apdu[] = {0, 3, 0, 0};
  auto a = f.dev.ingest(make_frames(cid, ctap::kCmdMsg, apdu).front(), std::nullopt);
  REQUIRE(a.reply[0][7] == static_cast<std::uint8_t>(ctap::HidErr::InvalidCmd));
  auto b = f.dev.ingest(make_frames(cid, ctap::kCmdLock, {}).front(), std::nullopt);
  REQUIRE(b.reply[0][7] == static_cast<std::uint8_t>(ctap::HidErr::InvalidCmd));
}

TEST_CASE("inter-packet timeout emits MSG_TIMEOUT on the assembling CID", "[hiddev]") {
  Fx f;
  auto cid = f.init();
  std::vector<std::uint8_t> payload(100, 0x22);
  auto frames = make_frames(cid, ctap::kCmdCbor, payload);
  const auto t0 = ctap::HidDevice::Clock::now();
  (void)f.dev.ingest(frames[0], std::nullopt, t0);
  REQUIRE_FALSE(f.dev.poll_timeout(t0 + std::chrono::milliseconds(100)).has_value());
  auto e = f.dev.poll_timeout(t0 + std::chrono::milliseconds(600));
  REQUIRE(e.has_value());
  REQUIRE(cid_of(*e) == cid);
  REQUIRE((*e)[7] == static_cast<std::uint8_t>(ctap::HidErr::MsgTimeout));
  REQUIRE_FALSE(f.dev.assembling());
}
