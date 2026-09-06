#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace swpk::ctap {

// authenticatorGetInfo (0x04) snapshot. Only fields the current build has
// code for are populated; see DESIGN.md "authenticatorGetInfo".
struct GetInfoSnapshot {
  std::vector<std::string> versions{"FIDO_2_0"};
  std::vector<std::string> extensions;  // empty until hmac-secret lands
  std::array<std::uint8_t, 16> aaguid{};
  struct Options {
    bool always_uv{false};
    std::optional<bool> client_pin;         // present only once PIN is implemented
    bool cred_mgmt{false};
    bool make_cred_uv_not_rqd{false};
    std::optional<bool> pin_uv_auth_token;  // present only once PIN is implemented
    bool plat{false};
    bool rk{true};
    bool up{true};
  } options;
  std::uint32_t max_msg_size{1200};
  std::vector<std::uint8_t> pin_protocols;  // empty until PIN lands; then {2}
  std::uint32_t max_creds_in_list{8};
  std::uint32_t max_cred_id_len{32};
  std::vector<std::string> transports{"usb"};
  std::vector<int> algorithms{-7};
  std::uint32_t firmware_version{1};
  std::uint32_t remaining_discoverable{0};  // key 0x14 (20)
};

// Canonical CTAP2 CBOR of the snapshot (map with integer keys).
std::vector<std::uint8_t> encode_get_info(const GetInfoSnapshot& s);

}  // namespace swpk::ctap
