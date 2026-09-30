#pragma once

// Presentation model for the credential list shown by the menu bar UI and
// reusable by any other front end. Pure functions over the store; no AppKit.

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/store/credential.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace swpk::ui {

struct KeyRow {
  std::string rp_id;
  std::string rp_name;
  std::string user_name;
  std::string user_display;
  std::string backend;      // "Secure Enclave" | "TPM 2.0" | "Software"
  std::string cred_id_hex;  // 64 hex chars
  bool u2f{false};          // CTAP1 registration (not discoverable)
  std::uint32_t sign_count{0};
  std::uint64_t created_unix{0};
  std::uint64_t last_used_unix{0};
};

// Human label for a key backend.
const char* backend_label(crypto::BackendKind k);

// Lowercase hex.
std::string hex_string(std::span<const std::uint8_t> v);

// Local time "YYYY-MM-DD HH:MM"; empty for 0 (never).
std::string format_unix_time(std::uint64_t unix_seconds);

// All credentials, sorted by rp_id, then user_name, then creation time.
std::vector<KeyRow> key_rows(const store::CredentialStore& store);

// One-line summary for the status menu, e.g. "3 passkeys · Secure Enclave".
std::string keys_summary(std::size_t count, const std::string& key_backend);

}  // namespace swpk::ui
