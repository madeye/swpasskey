#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "fake_transport.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <thread>

using namespace swpk;
using namespace swpk::test;
using namespace std::chrono_literals;

namespace {

// Handler whose "makeCredential" blocks in a fake UP wait until cancelled or
// released, publishing UPNEEDED while blocked. getInfo answers instantly.
class SlowHandler final : public ctap::RequestHandler {
public:
  std::atomic<bool> release{false};
  std::atomic<int> calls{0};

  Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t> req,
                                                ctap::CancelToken& cancel) override {
    ++calls;
    if (req.empty()) return std::unexpected(Status::InvalidLength);
    if (req[0] == 0x04) return std::vector<std::uint8_t>{0xA0};
    if (req[0] == 0x01) {
      cancel.set_up_needed(true);
      while (!release.load()) {
        if (cancel.is_cancelled()) {
          cancel.set_up_needed(false);
          return std::unexpected(Status::KeepaliveCancel);
        }
        std::this_thread::sleep_for(2ms);
      }
      cancel.set_up_needed(false);
      std::this_thread::sleep_for(250ms);  // "TPM sign" while PROCESSING
      return std::vector<std::uint8_t>{0xA0};
    }
    return std::unexpected(Status::InvalidCommand);
  }
  std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t>, ctap::CancelToken&) override {
    return {0x6D, 0x00};
  }
  bool supports_u2f() const override { return false; }
};

struct Rig {
  FakeTransport t;
  SlowHandler h;
  crypto::Provider rng;
  daemon::Loop loop{t, h, rng};
  std::thread hid;
  Rig() { hid = std::thread([&] { loop.run(); }); }
  ~Rig() {
    loop.stop();
    hid.join();
  }
  std::uint32_t init() {
    const std::uint8_t nonce[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    t.host_write(make_frames(ctap::kBroadcastCid, ctap::kCmdInit, nonce).front());
    auto r = t.host_read(2s);
    REQUIRE(r.has_value());
    REQUIRE(cmd_of(*r) == ctap::kCmdInit);
    return static_cast<std::uint32_t>((*r)[15]) | (static_cast<std::uint32_t>((*r)[16]) << 8) |
           (static_cast<std::uint32_t>((*r)[17]) << 16) | (static_cast<std::uint32_t>((*r)[18]) << 24);
  }
};

}  // namespace

TEST_CASE("getInfo produces a response and zero keepalives", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t gi[] = {0x04};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, gi).front());
  auto resp = r.t.host_read(2s);
  REQUIRE(resp.has_value());
  REQUIRE(cid_of(*resp) == cid);
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE(bcnt_of(*resp) == 2);
  REQUIRE((*resp)[7] == 0x00);
  REQUIRE((*resp)[8] == 0xA0);
  std::this_thread::sleep_for(150ms);
  REQUIRE(r.t.host_drain().empty());
  REQUIRE(r.loop.stats().keepalives == 0);
  REQUIRE(r.loop.stats().cbor_ok == 1);
}

TEST_CASE("UPNEEDED keepalives while blocked, PROCESSING after, then response", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  int upneeded = 0;
  for (int i = 0; i < 3; ++i) {
    auto k = r.t.host_read(1s);
    REQUIRE(k.has_value());
    REQUIRE(cmd_of(*k) == ctap::kCmdKeepalive);
    REQUIRE(cid_of(*k) == cid);
    if ((*k)[7] == ctap::kKeepaliveUpNeeded) ++upneeded;
  }
  REQUIRE(upneeded == 3);
  r.h.release = true;
  int processing = 0;
  std::optional<hid::Report> resp;
  for (int i = 0; i < 20; ++i) {
    auto k = r.t.host_read(1s);
    REQUIRE(k.has_value());
    if (cmd_of(*k) == ctap::kCmdKeepalive) {
      if ((*k)[7] == ctap::kKeepaliveProcessing) ++processing;
      continue;
    }
    resp = *k;
    break;
  }
  REQUIRE(resp.has_value());
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE((*resp)[7] == 0x00);
  REQUIRE(processing >= 1);
  // Nothing after the response.
  REQUIRE_FALSE(r.t.host_read(150ms).has_value());
}

TEST_CASE("CANCEL during UP yields KEEPALIVE_CANCEL on the same CID", "[loop]") {
  Rig r;
  auto cid = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(cid, ctap::kCmdCbor, mc).front());
  auto k = r.t.host_read(1s);
  REQUIRE(k.has_value());
  REQUIRE(cmd_of(*k) == ctap::kCmdKeepalive);
  r.t.host_write(make_frames(cid, ctap::kCmdCancel, {}).front());
  std::optional<hid::Report> resp;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cmd_of(*p) == ctap::kCmdKeepalive) continue;
    resp = *p;
    break;
  }
  REQUIRE(resp.has_value());
  REQUIRE(cmd_of(*resp) == ctap::kCmdCbor);
  REQUIRE(bcnt_of(*resp) == 1);
  REQUIRE((*resp)[7] == static_cast<std::uint8_t>(Status::KeepaliveCancel));
  REQUIRE(r.loop.stats().cancels == 1);
}

TEST_CASE("second channel gets CHANNEL_BUSY while first is in flight", "[loop]") {
  Rig r;
  auto c1 = r.init();
  auto c2 = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(c1, ctap::kCmdCbor, mc).front());
  REQUIRE(r.t.host_read(1s).has_value());  // a keepalive: worker is busy
  const std::uint8_t gi[] = {0x04};
  r.t.host_write(make_frames(c2, ctap::kCmdCbor, gi).front());
  std::optional<hid::Report> err;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cid_of(*p) == c2) {
      err = *p;
      break;
    }
  }
  REQUIRE(err.has_value());
  REQUIRE(cmd_of(*err) == ctap::kCmdError);
  REQUIRE((*err)[7] == static_cast<std::uint8_t>(ctap::HidErr::ChannelBusy));
  r.h.release = true;
}

TEST_CASE("PING is answered on the HID thread while the worker is busy", "[loop]") {
  Rig r;
  auto c1 = r.init();
  auto c2 = r.init();
  const std::uint8_t mc[] = {0x01};
  r.t.host_write(make_frames(c1, ctap::kCmdCbor, mc).front());
  REQUIRE(r.t.host_read(1s).has_value());
  const std::uint8_t ping[] = {1, 2, 3};
  r.t.host_write(make_frames(c2, ctap::kCmdPing, ping).front());
  std::optional<hid::Report> pong;
  for (int i = 0; i < 20; ++i) {
    auto p = r.t.host_read(1s);
    REQUIRE(p.has_value());
    if (cid_of(*p) == c2) {
      pong = *p;
      break;
    }
  }
  REQUIRE(pong.has_value());
  REQUIRE(cmd_of(*pong) == ctap::kCmdPing);
  REQUIRE(bcnt_of(*pong) == 3);
  r.h.release = true;
}
