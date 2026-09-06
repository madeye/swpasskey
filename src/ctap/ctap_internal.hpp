// Internal helpers shared by makeCredential / getAssertion / clientPIN.
// Not a public header.
#pragma once

#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/status.hpp"
#include "swpasskey/store/credential.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace swpk::ctap::detail {

using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;

// authData flag bits (WebAuthn L3 §6.1).
inline constexpr std::uint8_t kFlagUp = 0x01;
inline constexpr std::uint8_t kFlagUv = 0x04;
inline constexpr std::uint8_t kFlagAt = 0x40;
inline constexpr std::uint8_t kFlagEd = 0x80;

struct PubKeyCredDescriptor {
  std::string type;
  std::vector<std::uint8_t> id;
};

struct RpEntity {
  std::string id;
  std::string name;
};

struct UserEntity {
  std::vector<std::uint8_t> id;
  std::string name;
  std::string display_name;
};

struct Options {
  std::optional<bool> rk;
  std::optional<bool> up;
  std::optional<bool> uv;
};

// Parsed extension inputs relevant to v1.
struct ExtensionsIn {
  std::optional<std::uint64_t> cred_protect;
  bool hmac_create_secret{false};     // makeCredential: "hmac-secret": true
  bool hmac_secret_present{false};    // getAssertion: "hmac-secret": {...}
  // getAssertion hmac-secret inputs (PR10)
  std::optional<crypto::P256PublicKey> hmac_key_agreement;
  std::vector<std::uint8_t> hmac_salt_enc;
  std::vector<std::uint8_t> hmac_salt_auth;
  std::uint64_t hmac_pin_protocol{1};
};

// Map-key iteration helper: reads an integer map key. Text keys → error.
Result<std::int64_t> read_int_key(cbor::Reader& r);

Result<PubKeyCredDescriptor> parse_descriptor(cbor::Reader& r);
Result<std::vector<PubKeyCredDescriptor>> parse_descriptor_list(cbor::Reader& r);
Result<RpEntity> parse_rp(cbor::Reader& r);
Result<UserEntity> parse_user(cbor::Reader& r);
Result<Options> parse_options(cbor::Reader& r);
Result<ExtensionsIn> parse_extensions(cbor::Reader& r);
// COSE_Key (EC2, P-256) as sent by platforms in keyAgreement fields.
Result<crypto::P256PublicKey> parse_cose_p256(cbor::Reader& r);
// pubKeyCredParams: true if an ES256 public-key entry exists.
Result<bool> parse_pub_key_cred_params_has_es256(cbor::Reader& r);

std::vector<std::uint8_t> encode_cose_p256(const crypto::P256PublicKey& pub);
std::vector<std::uint8_t> encode_descriptor(std::span<const std::uint8_t> cred_id);
// user entity for getAssertion; `full` adds name/displayName (only when UV=1).
std::vector<std::uint8_t> encode_user(const UserEntity& u, bool full);

// rpIdHash ‖ flags ‖ signCount ‖ [attestedCredentialData] ‖ [extensions]
std::vector<std::uint8_t> build_auth_data(std::span<const std::uint8_t, 32> rp_id_hash,
                                          std::uint8_t flags, std::uint32_t sign_count,
                                          std::span<const std::uint8_t> attested_cred_data,
                                          std::span<const std::uint8_t> extensions_cbor);
std::vector<std::uint8_t> build_attested_credential_data(
    std::span<const std::uint8_t, 16> aaguid, std::span<const std::uint8_t> cred_id,
    const crypto::P256PublicKey& pub);

}  // namespace swpk::ctap::detail

namespace swpk::ctap::detail {

// getNextAssertion state (expires 30 s after getAssertion).
struct AssertionState {
  std::vector<store::Credential> remaining;
  std::array<std::uint8_t, 32> rp_id_hash{};
  std::array<std::uint8_t, 32> client_data_hash{};
  std::uint8_t flags{};
  bool bump_counter{true};
  ExtensionsIn ext;
  std::chrono::steady_clock::time_point expiry;
};

}  // namespace swpk::ctap::detail
