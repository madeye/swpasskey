#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace swpk {

// Packed self-attestation AAGUID. Not in the FIDO MDS. Do not impersonate
// any certified hardware model.
inline constexpr std::array<std::uint8_t, 16> kAaguid{
    0x6f, 0xb1, 0xdf, 0xdd, 0x51, 0xc0, 0x43, 0xa0,
    0xa6, 0xf2, 0xf7, 0x48, 0x12, 0xcb, 0xf8, 0xfb};

// pid.codes VID. 0xF1D0 is development-only until an official PID is assigned.
inline constexpr std::uint16_t kUsbVid = 0x1209;
inline constexpr std::uint16_t kUsbPid = 0xF1D0;

inline constexpr std::string_view kVersion = "0.1.0";

}  // namespace swpk
