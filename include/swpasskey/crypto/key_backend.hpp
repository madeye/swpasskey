#pragma once

#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
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
  // Release whatever wrap_secret allocated outside the store (SE Keychain
  // item). Default: nothing (TPM blobs and software secrets live in the store).
  virtual Result<void> destroy_secret(std::span<const std::uint8_t> /*wrapped*/) { return {}; }
  // After authenticatorReset: rebuild install-bound state (TPM primary from
  // the freshly generated seed). Default: nothing.
  virtual Result<void> reinit_after_reset() { return {}; }
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

// TPM 2.0 install-bound parameters (DESIGN.md "Linux TPM 2.0"). Generated
// once by the store and handed to the backend on first use.
struct Tpm2Params {
  std::array<std::uint8_t, 32> srk_unique_seed{};
  std::array<std::uint8_t, 32> object_auth{};
};

struct ProbeOptions {
  std::string pref{"auto"};  // auto|se|tpm|software
  // Supplies (or generates) the TPM seeds. Required for pref=tpm / auto on Linux.
  std::function<Result<Tpm2Params>()> tpm_params;
  // TCTI override (e.g. "swtpm:host=127.0.0.1,port=2321"); default device:/dev/tpmrm0.
  std::string tpm_tcti;
  // SWPASSKEY_TPM_UNSAFE_NOTPMRM=1: also try /dev/tpm0 (no kernel RM).
  bool tpm_allow_notpmrm{false};
};

// --key-backend=auto|se|tpm|software. `detail` receives a one-line reason
// for the startup log ("probe=ok tcti=..." / "probe=se_unavailable err=...").
// Returns nullptr when an explicit backend is unavailable (hard error for
// the caller); `auto` never returns nullptr.
std::unique_ptr<KeyBackend> probe_key_backend(const ProbeOptions& opt, std::string& detail);
std::unique_ptr<KeyBackend> probe_key_backend(std::string_view pref);

// Platform factories (nullptr + reason when unavailable).
#if defined(__APPLE__)
std::unique_ptr<KeyBackend> make_se_key_backend(std::string& why);
#endif
#if defined(SWPASSKEY_TPM)
std::unique_ptr<KeyBackend> make_tpm2_key_backend(const ProbeOptions& opt, std::string& why);
#endif

}  // namespace swpk::crypto
