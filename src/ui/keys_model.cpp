#include "swpasskey/ui/keys_model.hpp"

#include <algorithm>
#include <ctime>

namespace swpk::ui {

const char* backend_label(crypto::BackendKind k) {
  switch (k) {
    case crypto::BackendKind::SecureEnclave:
      return "Secure Enclave";
    case crypto::BackendKind::Tpm2:
      return "TPM 2.0";
    case crypto::BackendKind::Software:
      return "Software";
  }
  return "Software";
}

std::string hex_string(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  s.reserve(v.size() * 2);
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

std::string format_unix_time(std::uint64_t unix_seconds) {
  if (unix_seconds == 0) {
    return {};
  }
  const std::time_t t = static_cast<std::time_t>(unix_seconds);
  std::tm tm{};
  if (localtime_r(&t, &tm) == nullptr) {
    return {};
  }
  char buf[32];
  if (std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", &tm) == 0) {
    return {};
  }
  return buf;
}

std::vector<KeyRow> key_rows(const store::CredentialStore& store) {
  std::vector<KeyRow> rows;
  for (const auto& c : store.all()) {
    KeyRow r;
    r.rp_id = c.rp_id;
    r.rp_name = c.rp_name;
    r.user_name = c.user_name;
    r.user_display = c.user_display;
    r.backend = backend_label(c.backend);
    r.cred_id_hex = hex_string(c.cred_id);
    r.u2f = !c.rk;
    r.sign_count = c.sign_count;
    r.created_unix = c.created_unix;
    r.last_used_unix = c.last_used_unix;
    rows.push_back(std::move(r));
  }
  std::stable_sort(rows.begin(), rows.end(), [](const KeyRow& a, const KeyRow& b) {
    if (a.rp_id != b.rp_id) return a.rp_id < b.rp_id;
    if (a.user_name != b.user_name) return a.user_name < b.user_name;
    return a.created_unix < b.created_unix;
  });
  return rows;
}

std::string keys_summary(std::size_t count, const std::string& key_backend) {
  std::string s = count == 0 ? "No passkeys" : std::to_string(count) + (count == 1 ? " passkey" : " passkeys");
  if (!key_backend.empty()) {
    s += " \xC2\xB7 " + key_backend;  // middle dot
  }
  return s;
}

}  // namespace swpk::ui
