#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace swpk::ctap {

inline constexpr std::uint32_t kBroadcastCid = 0xFFFFFFFFu;
inline constexpr std::uint8_t kTypeInit = 0x80;
inline constexpr std::uint8_t kCmdPing = 0x01;
inline constexpr std::uint8_t kCmdMsg = 0x03;
inline constexpr std::uint8_t kCmdLock = 0x04;
inline constexpr std::uint8_t kCmdInit = 0x06;
inline constexpr std::uint8_t kCmdWink = 0x08;
inline constexpr std::uint8_t kCmdCbor = 0x10;
inline constexpr std::uint8_t kCmdCancel = 0x11;
inline constexpr std::uint8_t kCmdKeepalive = 0x3B;
inline constexpr std::uint8_t kCmdError = 0x3F;
inline constexpr std::uint8_t kCapWink = 0x01;
inline constexpr std::uint8_t kCapCbor = 0x04;
inline constexpr std::uint8_t kCapNmsg = 0x08;
inline constexpr std::uint8_t kKeepaliveProcessing = 0x01;
inline constexpr std::uint8_t kKeepaliveUpNeeded = 0x02;
inline constexpr std::uint8_t kHidVersion = 0x02;
inline constexpr std::size_t kMaxMessage = 7609;
inline constexpr std::size_t kInitPayload = 57;
inline constexpr std::size_t kContPayload = 59;
inline constexpr auto kInterPacketTimeout = std::chrono::milliseconds(500);
inline constexpr auto kKeepaliveInterval = std::chrono::milliseconds(100);
inline constexpr auto kUserActionTimeout = std::chrono::seconds(30);

}  // namespace swpk::ctap
