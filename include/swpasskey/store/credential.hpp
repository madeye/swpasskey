#pragma once

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace swpk::crypto {
class Provider;
}

namespace swpk::store {

inline constexpr std::size_t kMaxCredentials = 100;

struct Credential {
  std::string rp_id;
  std::array<std::uint8_t, 32> rp_id_hash{};
  std::string rp_name;
  std::vector<std::uint8_t> user_id;
  std::string user_name;
  std::string user_display;
  std::array<std::uint8_t, 32> cred_id{};
  crypto::BackendKind backend{crypto::BackendKind::Software};
  std::vector<std::uint8_t> handle;  // empty for software
  std::vector<std::uint8_t> priv;    // software scalar only; empty for HW
  crypto::P256PublicKey pub{};
  std::uint32_t sign_count{1};
  std::uint64_t created_unix{};
  std::uint64_t last_used_unix{};
  std::vector<std::uint8_t> cred_random;  // wrap_secret output (64 B dual credRandom)
};

struct PinState {
  std::optional<std::array<std::uint8_t, 16>> hash;  // LEFT(SHA-256(PIN), 16)
  std::uint8_t retries{8};
};

struct TpmState {
  bool present{false};
  std::array<std::uint8_t, 32> srk_unique_seed{};
  std::array<std::uint8_t, 32> object_auth{};
};

struct U2fAttestation {
  std::vector<std::uint8_t> priv;      // software P-256 scalar
  std::vector<std::uint8_t> cert_der;  // self-signed X.509
};

// Persistence hooks. The in-memory store (tests, PR4) has none; the on-disk
// store (PR5) installs a writer that serialises + encrypts + renames.
class Persister {
public:
  virtual ~Persister() = default;
  virtual Result<void> save(std::span<const std::uint8_t> plaintext) = 0;
  // Factory reset: zero-overwrite the old file and rotate the DEK before the
  // fresh (empty) store is saved. Default: nothing.
  virtual Result<void> reset() { return {}; }
};

// Thread-safe credential store. Every mutation flushes before returning so
// the HID thread can only send a success response after the counter / new
// row is durable (DESIGN.md "Persist-before-send").
class CredentialStore {
public:
  // In-memory store with no persistence.
  static std::unique_ptr<CredentialStore> open_memory();
  // Store backed by an existing plaintext snapshot (PR5 decrypts the file and
  // hands it here) plus a persister for subsequent flushes. `plaintext` empty
  // means "fresh store".
  static Result<std::unique_ptr<CredentialStore>> open_with(
      std::span<const std::uint8_t> plaintext, std::unique_ptr<Persister> persister);

  // Credentials
  Result<void> put(Credential c);
  std::vector<Credential> find_by_rp(std::span<const std::uint8_t, 32> rp_id_hash) const;
  std::optional<Credential> find(std::span<const std::uint8_t, 32> rp_id_hash,
                                 std::span<const std::uint8_t> cred_id) const;
  std::optional<Credential> find_by_id(std::span<const std::uint8_t> cred_id) const;
  Result<void> update_count_and_used(std::span<const std::uint8_t> cred_id,
                                     std::uint32_t new_count, std::uint64_t now_unix);
  Result<void> erase(std::span<const std::uint8_t> cred_id);
  std::vector<Credential> all() const;
  std::size_t size() const;
  std::size_t remaining() const;
  std::array<std::size_t, 3> count_by_backend() const;

  // Wipes everything (creds, PIN, TPM seeds, U2F attestation) and flushes.
  // `destroy` is invoked per credential before the row is dropped.
  Result<void> factory_reset(
      const std::function<void(const Credential&)>& destroy = nullptr);

  // PIN
  PinState pin() const;
  Result<void> set_pin(PinState state);

  // TPM (generate-on-first-use)
  Result<TpmState> tpm_state_or_create(crypto::Provider& rng);
  Result<void> clear_tpm_state();

  // U2F attestation (PR11)
  std::optional<U2fAttestation> u2f_attestation() const;
  Result<void> set_u2f_attestation(U2fAttestation a);

  // Identity
  std::string serial() const;
  Result<void> set_serial(std::string serial);
  std::array<std::uint8_t, 16> install_id() const;
  void set_install_id(std::array<std::uint8_t, 16> id);

  // Force a write through the persister (no-op for the in-memory store).
  Result<void> flush();
  // Canonical CBOR plaintext (DESIGN.md "File format"). Public for tests.
  std::vector<std::uint8_t> serialize() const;
  static Result<void> validate(const Credential& c);

private:
  CredentialStore() = default;
  Result<void> load_locked(std::span<const std::uint8_t> plaintext);
  Result<void> flush_locked();
  std::vector<std::uint8_t> serialize_locked() const;

  mutable std::mutex mu_;
  std::vector<Credential> creds_;
  PinState pin_;
  TpmState tpm_;
  std::optional<U2fAttestation> u2f_;
  std::string serial_;
  std::array<std::uint8_t, 16> install_id_{};
  std::unique_ptr<Persister> persister_;
};

}  // namespace swpk::store
