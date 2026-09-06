#pragma once

#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace swpk::crypto {

enum class BackendKind : std::uint8_t { Software = 0, Tpm2 = 1, SecureEnclave = 2 };

struct P256PublicKey {
  std::array<std::uint8_t, 32> x{};
  std::array<std::uint8_t, 32> y{};
};

class SigningKey {
public:
  virtual ~SigningKey() = default;
  virtual BackendKind kind() const = 0;
  virtual P256PublicKey pub() const = 0;
  virtual Result<std::vector<std::uint8_t>> sign_der(
      std::span<const std::uint8_t> message) const = 0;
  virtual std::vector<std::uint8_t> persist_handle() const = 0;
};

class KeyBackend {
public:
  virtual ~KeyBackend() = default;
  virtual BackendKind kind() const = 0;
  virtual Result<std::unique_ptr<SigningKey>> generate() = 0;
  virtual Result<std::unique_ptr<SigningKey>> load(std::span<const std::uint8_t> handle,
                                                   const P256PublicKey& pub) = 0;
  virtual Result<void> destroy(std::span<const std::uint8_t> handle) = 0;
  virtual Result<std::vector<std::uint8_t>> wrap_secret(
      std::span<const std::uint8_t> secret) = 0;
  virtual Result<std::vector<std::uint8_t>> unwrap_secret(
      std::span<const std::uint8_t> wrapped) = 0;
};

class SoftwareKeyBackend final : public KeyBackend {
public:
  BackendKind kind() const override { return BackendKind::Software; }
  Result<std::unique_ptr<SigningKey>> generate() override;
  Result<std::unique_ptr<SigningKey>> load(std::span<const std::uint8_t> handle,
                                           const P256PublicKey& pub) override;
  Result<void> destroy(std::span<const std::uint8_t> handle) override;
  Result<std::vector<std::uint8_t>> wrap_secret(std::span<const std::uint8_t> secret) override;
  Result<std::vector<std::uint8_t>> unwrap_secret(std::span<const std::uint8_t> wrapped) override;

  Result<std::unique_ptr<SigningKey>> load_from_scalar(
      std::span<const std::uint8_t, 32> scalar);
  static Result<std::array<std::uint8_t, 32>> export_scalar_for_store(const SigningKey& key);
};

std::unique_ptr<KeyBackend> probe_key_backend(std::string_view pref);

}  // namespace swpk::crypto
