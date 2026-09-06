#include "swpasskey/ctap/hid_framer.hpp"

#include <algorithm>
#include <cstring>

namespace swpk::ctap {
namespace {

std::uint32_t read_cid_le(std::span<const std::uint8_t> p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

void write_cid_le(std::span<std::uint8_t> p, std::uint32_t cid) {
  p[0] = static_cast<std::uint8_t>(cid);
  p[1] = static_cast<std::uint8_t>(cid >> 8);
  p[2] = static_cast<std::uint8_t>(cid >> 16);
  p[3] = static_cast<std::uint8_t>(cid >> 24);
}

std::uint16_t read_u16_be(std::span<const std::uint8_t> p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                    static_cast<std::uint16_t>(p[1]));
}

void write_u16_be(std::span<std::uint8_t> p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v);
}

}  // namespace

std::expected<std::optional<Message>, HidErr> HidFramer::ingest(
    std::span<const std::uint8_t, swpk::hid::kReportSize> report) {
  const std::uint32_t cid = read_cid_le(report);
  if (cid == 0) {
    return std::unexpected(HidErr::InvalidChannel);
  }

  const std::uint8_t b4 = report[4];
  if ((b4 & kTypeInit) != 0) {
    const std::uint8_t cmd = static_cast<std::uint8_t>(b4 & 0x7F);
    const std::uint16_t bcnt = read_u16_be(report.subspan(5, 2));
    if (bcnt > kMaxMessage) {
      assembly_.reset();
      return std::unexpected(HidErr::InvalidLen);
    }
    if (assembly_ && assembly_->cid != cid) {
      return std::unexpected(HidErr::ChannelBusy);
    }
    Assembly a;
    a.cid = cid;
    a.cmd = cmd;
    a.bcnt = bcnt;
    a.next_seq = 0;
    const std::size_t take =
        std::min(static_cast<std::size_t>(bcnt), kInitPayload);
    a.buf.assign(report.begin() + 7, report.begin() + 7 + static_cast<std::ptrdiff_t>(take));
    if (a.buf.size() >= bcnt) {
      a.buf.resize(bcnt);
      Message m{a.cid, a.cmd, std::move(a.buf)};
      assembly_.reset();
      return m;
    }
    assembly_ = std::move(a);
    return std::optional<Message>{};
  }

  if (!assembly_ || assembly_->cid != cid) {
    return std::unexpected(HidErr::InvalidSeq);
  }
  if (b4 != assembly_->next_seq) {
    assembly_.reset();
    return std::unexpected(HidErr::InvalidSeq);
  }
  const std::size_t remaining = static_cast<std::size_t>(assembly_->bcnt) - assembly_->buf.size();
  const std::size_t take = std::min(remaining, kContPayload);
  assembly_->buf.insert(assembly_->buf.end(), report.begin() + 5,
                        report.begin() + 5 + static_cast<std::ptrdiff_t>(take));
  assembly_->next_seq = static_cast<std::uint8_t>(assembly_->next_seq + 1);
  if (assembly_->next_seq > 127) {
    assembly_.reset();
    return std::unexpected(HidErr::InvalidLen);
  }
  if (assembly_->buf.size() >= assembly_->bcnt) {
    assembly_->buf.resize(assembly_->bcnt);
    Message m{assembly_->cid, assembly_->cmd, std::move(assembly_->buf)};
    assembly_.reset();
    return m;
  }
  return std::optional<Message>{};
}

std::vector<std::array<std::uint8_t, swpk::hid::kReportSize>> HidFramer::frame(
    const Message& msg) const {
  std::vector<std::array<std::uint8_t, swpk::hid::kReportSize>> out;
  if (msg.payload.size() > kMaxMessage) {
    return out;
  }
  std::array<std::uint8_t, swpk::hid::kReportSize> pkt{};
  write_cid_le(pkt, msg.cid);
  pkt[4] = static_cast<std::uint8_t>(kTypeInit | msg.cmd);
  write_u16_be(std::span<std::uint8_t>(pkt.data() + 5, 2),
               static_cast<std::uint16_t>(msg.payload.size()));
  const std::size_t first = std::min(msg.payload.size(), kInitPayload);
  if (first > 0) {
    std::memcpy(pkt.data() + 7, msg.payload.data(), first);
  }
  out.push_back(pkt);
  std::size_t off = first;
  std::uint8_t seq = 0;
  while (off < msg.payload.size()) {
    pkt.fill(0);
    write_cid_le(pkt, msg.cid);
    pkt[4] = seq++;
    const std::size_t n = std::min(msg.payload.size() - off, kContPayload);
    std::memcpy(pkt.data() + 5, msg.payload.data() + off, n);
    out.push_back(pkt);
    off += n;
  }
  return out;
}

void HidFramer::cancel(std::uint32_t cid) {
  if (assembly_ && assembly_->cid == cid) {
    assembly_.reset();
  }
}

std::optional<HidErr> HidFramer::on_timeout() {
  if (!assembly_) {
    return std::nullopt;
  }
  assembly_.reset();
  return HidErr::MsgTimeout;
}

}  // namespace swpk::ctap
