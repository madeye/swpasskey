#pragma once

#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace swpk::store {

// Holds the 32-byte store DEK (DESIGN.md K12). One item per install_id.
class Keychain {
public:
  virtual ~Keychain() = default;
  virtual Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(
      std::string_view install_id_hex) = 0;
  virtual Result<void> store_dek(std::string_view install_id_hex,
                                 std::span<const std::uint8_t, 32> dek) = 0;
  virtual Result<void> delete_dek(std::string_view install_id_hex) = 0;
  virtual const char* name() const = 0;
};

// macOS Keychain (service io.github.swpasskey, account dek) or Linux
// libsecret (schema io.github.swpasskey.dek, attr install_id). Returns
// nullptr when the platform backend was not compiled in.
std::unique_ptr<Keychain> make_os_keychain();

// 0600 file next to the store (credentials.bin.dek). Weaker: see DESIGN.md.
std::unique_ptr<Keychain> make_file_keychain(std::filesystem::path path);

// Tries `primary` and falls back to `fallback` (logging a warning) when the
// primary fails or is null.
std::unique_ptr<Keychain> make_fallback_keychain(std::unique_ptr<Keychain> primary,
                                                 std::unique_ptr<Keychain> fallback);

// Tests only.
class MemoryKeychain final : public Keychain {
public:
  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view id) override;
  Result<void> store_dek(std::string_view id, std::span<const std::uint8_t, 32> dek) override;
  Result<void> delete_dek(std::string_view id) override;
  const char* name() const override { return "memory"; }
  bool fail{false};

private:
  std::string id_;
  std::optional<std::array<std::uint8_t, 32>> dek_;
};

}  // namespace swpk::store
