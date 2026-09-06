#pragma once

#include <cstddef>
#include <cstdint>

namespace swpk::hid {

inline constexpr std::uint16_t kUsagePage = 0xF1D0;
inline constexpr std::uint8_t kUsageCtapHid = 0x01;
inline constexpr std::size_t kReportSize = 64;

inline constexpr std::uint8_t kReportDescriptor[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO)
    0x09, 0x01,        // Usage (CTAPHID)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (DATA_IN)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x81, 0x02,        //   Input (Data, Var, Abs)
    0x09, 0x21,        //   Usage (DATA_OUT)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x91, 0x02,        //   Output (Data, Var, Abs)
    0xC0               // End Collection
};

}  // namespace swpk::hid
