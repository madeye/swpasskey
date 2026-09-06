#include "swpasskey/ctap/hid_framer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <vector>

using swpk::ctap::HidErr;
using swpk::ctap::HidFramer;
using swpk::ctap::Message;
using swpk::hid::kReportSize;

static std::array<std::uint8_t, kReportSize> init_pkt(std::uint32_t cid, std::uint8_t cmd,
                                                      std::span<const std::uint8_t> payload) {
  std::array<std::uint8_t, kReportSize> p{};
  p[0] = static_cast<std::uint8_t>(cid);
  p[1] = static_cast<std::uint8_t>(cid >> 8);
  p[2] = static_cast<std::uint8_t>(cid >> 16);
  p[3] = static_cast<std::uint8_t>(cid >> 24);
  p[4] = static_cast<std::uint8_t>(0x80 | cmd);
  p[5] = static_cast<std::uint8_t>(payload.size() >> 8);
  p[6] = static_cast<std::uint8_t>(payload.size());
  const auto n = std::min(payload.size(), std::size_t{57});
  if (n > 0) {
    std::memcpy(p.data() + 7, payload.data(), n);
  }
  return p;
}

TEST_CASE("single-packet CBOR round trip", "[hid]") {
  HidFramer f;
  const std::uint8_t body[] = {0x04};
  auto pkt = init_pkt(0x11223344, swpk::ctap::kCmdCbor, body);
  auto r = f.ingest(pkt);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  REQUIRE((*r)->cid == 0x11223344);
  REQUIRE((*r)->cmd == swpk::ctap::kCmdCbor);
  REQUIRE((*r)->payload.size() == 1);
  REQUIRE((*r)->payload[0] == 0x04);

  auto frames = f.frame(**r);
  REQUIRE(frames.size() == 1);
  REQUIRE(frames[0] == pkt);
}

TEST_CASE("two-packet CONT sequence", "[hid]") {
  HidFramer f;
  std::vector<std::uint8_t> payload(80, 0xAB);
  Message m{0x01020304, swpk::ctap::kCmdPing, payload};
  auto frames = f.frame(m);
  REQUIRE(frames.size() == 2);
  auto a = f.ingest(frames[0]);
  REQUIRE(a.has_value());
  REQUIRE_FALSE(a->has_value());
  auto b = f.ingest(frames[1]);
  REQUIRE(b.has_value());
  REQUIRE(b->has_value());
  REQUIRE((*b)->payload == payload);
}

TEST_CASE("SEQ gap is InvalidSeq", "[hid]") {
  HidFramer f;
  std::vector<std::uint8_t> payload(80, 0x01);
  auto frames = f.frame(Message{1, swpk::ctap::kCmdPing, payload});
  REQUIRE(f.ingest(frames[0]).has_value());
  frames[1][4] = 5;  // wrong seq
  auto r = f.ingest(frames[1]);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == HidErr::InvalidSeq);
}

TEST_CASE("BCNT too large", "[hid]") {
  HidFramer f;
  auto pkt = init_pkt(1, swpk::ctap::kCmdPing, {});
  pkt[5] = 0x20;
  pkt[6] = 0x00;  // 8192 > 7609
  auto r = f.ingest(pkt);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == HidErr::InvalidLen);
}

TEST_CASE("interleaved CID is ChannelBusy", "[hid]") {
  HidFramer f;
  std::vector<std::uint8_t> payload(80, 0x02);
  auto a = f.frame(Message{1, swpk::ctap::kCmdPing, payload});
  REQUIRE(f.ingest(a[0]).has_value());
  auto b = init_pkt(2, swpk::ctap::kCmdCbor, std::array<std::uint8_t, 1>{0x04});
  auto r = f.ingest(b);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == HidErr::ChannelBusy);
}

TEST_CASE("cancel mid-CONT", "[hid]") {
  HidFramer f;
  std::vector<std::uint8_t> payload(80, 0x03);
  auto frames = f.frame(Message{9, swpk::ctap::kCmdPing, payload});
  REQUIRE(f.ingest(frames[0]).has_value());
  f.cancel(9);
  auto r = f.ingest(frames[1]);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == HidErr::InvalidSeq);
}

TEST_CASE("CID 0 is InvalidChannel", "[hid]") {
  HidFramer f;
  auto pkt = init_pkt(0, swpk::ctap::kCmdPing, {});
  auto r = f.ingest(pkt);
  REQUIRE_FALSE(r.has_value());
  REQUIRE(r.error() == HidErr::InvalidChannel);
}
