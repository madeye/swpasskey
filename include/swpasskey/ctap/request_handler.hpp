#pragma once

#include "swpasskey/ctap/cancel_token.hpp"
#include "swpasskey/status.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace swpk::ctap {

// What the authenticator worker thread calls. Implemented by Authenticator;
// tests substitute fakes to drive the HID loop.
class RequestHandler {
public:
  virtual ~RequestHandler() = default;
  // CTAPHID_CBOR payload (cmd || cbor). On success returns the CBOR body;
  // the HID layer prefixes status 0x00. On error only the status byte is sent.
  virtual Result<std::vector<std::uint8_t>> handle_cbor(std::span<const std::uint8_t> request,
                                                        CancelToken& cancel) = 0;
  // CTAPHID_MSG payload (U2F APDU). Returns the full response APDU (data || SW1 SW2).
  virtual std::vector<std::uint8_t> handle_u2f(std::span<const std::uint8_t> request,
                                               CancelToken& cancel) = 0;
  virtual bool supports_u2f() const = 0;
};

}  // namespace swpk::ctap
