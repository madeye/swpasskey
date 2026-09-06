#pragma once

#include <cstdint>
#include <expected>

namespace swpk {

// CTAP2 status bytes. HID-only codes (InvalidSeq, Timeout, ChannelBusy, …)
// live in hid::HidErr, not here. handle_cbor never returns HID codes as a
// CBOR status byte.
enum class Status : std::uint8_t {
  Ok                     = 0x00,
  InvalidCommand         = 0x01,
  InvalidParameter       = 0x02,
  InvalidLength          = 0x03,
  CborUnexpectedType     = 0x11,
  InvalidCbor            = 0x12,
  MissingParameter       = 0x14,
  LimitExceeded          = 0x15,
  CredentialExcluded     = 0x19,
  Processing             = 0x21,
  InvalidCredential      = 0x22,
  UnsupportedAlgorithm   = 0x26,
  OperationDenied        = 0x27,
  KeyStoreFull           = 0x28,
  UnsupportedOption      = 0x2B,
  InvalidOption          = 0x2C,
  KeepaliveCancel        = 0x2D,
  NoCredentials          = 0x2E,
  UserActionTimeout      = 0x2F,
  NotAllowed             = 0x30,
  PinInvalid             = 0x31,
  PinBlocked             = 0x32,
  PinAuthInvalid         = 0x33,
  PinAuthBlocked         = 0x34,
  PinNotSet              = 0x35,
  PuattRequired          = 0x36,
  PinPolicyViolation     = 0x37,
  RequestTooLarge        = 0x39,
  ActionTimeout          = 0x3A,
  UpRequired             = 0x3B,
  InvalidSubcommand      = 0x3E,
  UnauthorizedPermission = 0x40,
  UnsupportedExtension   = 0x4B,
  Other                  = 0x7F,
};

template <class T>
using Result = std::expected<T, Status>;

}  // namespace swpk
