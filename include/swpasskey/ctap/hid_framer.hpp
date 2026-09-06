#pragma once

#include "swpasskey/ctap/hid_defs.hpp"
#include "swpasskey/hid/report_descriptor.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace swpk::ctap {

struct Message {
  std::uint32_t cid{};
  std::uint8_t cmd{};  // without TYPE_INIT; e.g. 0x10 for CBOR
  std::vector<std::uint8_t> payload;
};

enum class HidErr : std::uint8_t {
  InvalidCmd     = 0x01,
  InvalidPar     = 0x02,
  InvalidLen     = 0x03,
  InvalidSeq     = 0x04,
  MsgTimeout     = 0x05,
  ChannelBusy    = 0x06,
  LockRequired   = 0x0A,
  InvalidChannel = 0x0B,
  Other          = 0x7F,
};

class HidFramer {
public:
  std::expected<std::optional<Message>, HidErr> ingest(
      std::span<const std::uint8_t, swpk::hid::kReportSize> report);
  std::vector<std::array<std::uint8_t, swpk::hid::kReportSize>> frame(
      const Message& msg) const;
  void cancel(std::uint32_t cid);
  std::optional<HidErr> on_timeout();

private:
  struct Assembly {
    std::uint32_t cid{};
    std::uint8_t cmd{};
    std::uint16_t bcnt{};
    std::uint8_t next_seq{};
    std::vector<std::uint8_t> buf;
  };
  std::optional<Assembly> assembly_;
};

}  // namespace swpk::ctap
