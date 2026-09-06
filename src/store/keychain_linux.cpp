// Linux DEK storage via libsecret (schema io.github.swpasskey.dek, attribute
// install_id). Compiled only when SWPASSKEY_LIBSECRET is defined; otherwise
// make_os_keychain() returns nullptr and the daemon uses the file fallback.
#if defined(__linux__)

#include "swpasskey/store/keychain.hpp"
#include "swpasskey/log/log.hpp"

#include <string>

#if defined(SWPASSKEY_LIBSECRET)
#include <libsecret/secret.h>
#endif

namespace swpk::store {

#if defined(SWPASSKEY_LIBSECRET)
namespace {

const SecretSchema* schema() {
  static const SecretSchema s = {
      "io.github.swpasskey.dek",
      SECRET_SCHEMA_NONE,
      {
          {"install_id", SECRET_SCHEMA_ATTRIBUTE_STRING},
          {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING},
      },
      0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
  };
  return &s;
}

std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

int unhex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

class LibsecretKeychain final : public Keychain {
public:
  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view install_id) override {
    GError* err = nullptr;
    gchar* pw = secret_password_lookup_sync(schema(), nullptr, &err, "install_id",
                                            std::string(install_id).c_str(), nullptr);
    if (err != nullptr) {
      log::warn("libsecret_lookup_failed", {{"err", err->message}});
      g_error_free(err);
      return std::unexpected(Status::Other);
    }
    if (pw == nullptr) {
      return std::optional<std::array<std::uint8_t, 32>>{};
    }
    std::string s(pw);
    secret_password_free(pw);
    if (s.size() != 64) {
      log::error("libsecret_dek_malformed");
      return std::unexpected(Status::Other);
    }
    std::array<std::uint8_t, 32> dek{};
    for (std::size_t i = 0; i < 32; ++i) {
      const int hi = unhex(s[2 * i]);
      const int lo = unhex(s[2 * i + 1]);
      if (hi < 0 || lo < 0) {
        return std::unexpected(Status::Other);
      }
      dek[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return std::optional<std::array<std::uint8_t, 32>>{dek};
  }

  Result<void> store_dek(std::string_view install_id, std::span<const std::uint8_t, 32> dek) override {
    GError* err = nullptr;
    const std::string h = hex(dek);
    const gboolean ok = secret_password_store_sync(schema(), SECRET_COLLECTION_DEFAULT,
                                                   "swpasskey store DEK", h.c_str(), nullptr, &err,
                                                   "install_id", std::string(install_id).c_str(),
                                                   nullptr);
    if (!ok || err != nullptr) {
      log::warn("libsecret_store_failed", {{"err", err ? err->message : "unknown"}});
      if (err) g_error_free(err);
      return std::unexpected(Status::Other);
    }
    return {};
  }

  Result<void> delete_dek(std::string_view install_id) override {
    GError* err = nullptr;
    secret_password_clear_sync(schema(), nullptr, &err, "install_id",
                               std::string(install_id).c_str(), nullptr);
    if (err != nullptr) {
      g_error_free(err);
      return std::unexpected(Status::Other);
    }
    return {};
  }

  const char* name() const override { return "libsecret"; }
};

}  // namespace

std::unique_ptr<Keychain> make_os_keychain() { return std::make_unique<LibsecretKeychain>(); }
#else
std::unique_ptr<Keychain> make_os_keychain() { return nullptr; }
#endif

}  // namespace swpk::store

#endif  // __linux__
