// authenticatorClientPIN (0x06), PIN protocol 2 only (DESIGN.md "PIN protocol 2").
#include "pin_state.hpp"

#include "ctap_internal.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <cstring>
#include <thread>

namespace swpk::ctap::detail {

using cbor::Reader;
using cbor::Writer;

namespace {

constexpr std::uint8_t kSubGetRetries = 0x01;
constexpr std::uint8_t kSubGetKeyAgreement = 0x02;
constexpr std::uint8_t kSubSetPin = 0x03;
constexpr std::uint8_t kSubChangePin = 0x04;
constexpr std::uint8_t kSubGetPinToken = 0x05;
constexpr std::uint8_t kSubGetTokenUsingUv = 0x06;
constexpr std::uint8_t kSubGetUvRetries = 0x07;
constexpr std::uint8_t kSubGetTokenUsingPin = 0x09;

constexpr std::uint8_t kSupportedPerms = kPermMc | kPermGa;

std::span<const std::uint8_t> bytes_of(const char* s) {
  return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s), std::strlen(s));
}

std::vector<std::uint8_t> encode_cose_ecdh(const crypto::P256PublicKey& pub) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_int(1), Writer::encode_int(2));     // kty EC2
  m.emplace_back(Writer::encode_int(3), Writer::encode_int(-25));   // alg ECDH-ES+HKDF-256
  m.emplace_back(Writer::encode_int(-1), Writer::encode_int(1));    // crv P-256
  m.emplace_back(Writer::encode_int(-2), Writer::encode_bstr(pub.x));
  m.emplace_back(Writer::encode_int(-3), Writer::encode_bstr(pub.y));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

std::chrono::milliseconds failure_delay(std::uint32_t consecutive,
                                        std::chrono::milliseconds base) {
  if (consecutive < 3) {
    return std::chrono::milliseconds(0);
  }
  auto d = base;
  const auto cap = base * 12;  // 5 s → 60 s
  for (std::uint32_t i = 3; i < consecutive && d < cap; ++i) {
    d *= 2;
  }
  return d > cap ? cap : d;
}

}  // namespace

SharedSecret::~SharedSecret() {
  OPENSSL_cleanse(hmac_key.data(), hmac_key.size());
  OPENSSL_cleanse(aes_key.data(), aes_key.size());
}

Result<SharedSecret> derive_shared_secret(crypto::Provider& p, std::span<const std::uint8_t, 32> z) {
  const std::uint8_t salt[32] = {};
  SharedSecret ss;
  auto h = p.hkdf_sha256(z, salt, bytes_of("CTAP2 HMAC key"));
  auto a = p.hkdf_sha256(z, salt, bytes_of("CTAP2 AES key"));
  if (!h || !a) {
    return std::unexpected(Status::Other);
  }
  ss.hmac_key = *h;
  ss.aes_key = *a;
  OPENSSL_cleanse(h->data(), h->size());
  OPENSSL_cleanse(a->data(), a->size());
  return ss;
}

Result<std::vector<std::uint8_t>> pin2_encrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> pt) {
  std::array<std::uint8_t, 16> iv{};
  if (!p.random(iv)) {
    return std::unexpected(Status::Other);
  }
  auto ct = p.aes256cbc_encrypt(ss.aes_key, iv, pt);
  if (!ct) {
    return std::unexpected(ct.error());
  }
  std::vector<std::uint8_t> out(iv.begin(), iv.end());
  out.insert(out.end(), ct->begin(), ct->end());
  return out;
}

Result<std::vector<std::uint8_t>> pin2_decrypt(crypto::Provider& p, const SharedSecret& ss,
                                               std::span<const std::uint8_t> ct) {
  if (ct.size() < 32 || ct.size() % 16 != 0) {
    return std::unexpected(Status::InvalidParameter);
  }
  std::array<std::uint8_t, 16> iv{};
  std::memcpy(iv.data(), ct.data(), 16);
  return p.aes256cbc_decrypt(ss.aes_key, iv, ct.subspan(16));
}

Result<std::array<std::uint8_t, 32>> pin2_authenticate(crypto::Provider& p,
                                                       std::span<const std::uint8_t> key,
                                                       std::span<const std::uint8_t> msg) {
  return p.hmac_sha256(key, msg);
}

PinManager::PinManager(crypto::Provider& crypto, store::CredentialStore& store,
                       std::chrono::milliseconds failure_delay_base,
                       std::chrono::milliseconds token_idle_timeout)
    : crypto_(crypto),
      store_(store),
      failure_delay_base_(failure_delay_base),
      token_idle_timeout_(token_idle_timeout) {
  (void)regenerate_key_agreement();
}

PinManager::~PinManager() { invalidate_token(); }

bool PinManager::pin_set() const { return store_.pin().hash.has_value(); }

Result<void> PinManager::set_pin_local(std::string_view pin) {
  std::size_t cps = 0;
  for (char c : pin) {
    if ((static_cast<unsigned char>(c) & 0xC0) != 0x80) {
      ++cps;
    }
  }
  if (pin.empty() || cps < 4 || cps > 63 || pin.size() > 63) {
    return std::unexpected(Status::PinPolicyViolation);
  }
  const auto digest = crypto_.sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
  store::PinState st;
  st.hash = std::array<std::uint8_t, 16>{};
  std::memcpy(st.hash->data(), digest.data(), 16);
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  consecutive_failures_ = 0;
  invalidate_token();
  log::info("pin_set_local");
  return {};
}

std::uint8_t PinManager::retries() const { return store_.pin().retries; }

void PinManager::invalidate_token() {
  if (token_) {
    OPENSSL_cleanse(token_->bytes.data(), token_->bytes.size());
    token_.reset();
  }
}

Result<void> PinManager::regenerate_key_agreement() {
  invalidate_token();
  auto k = crypto_.generate_p256_ephemeral();
  if (!k) {
    return std::unexpected(k.error());
  }
  ka_ = std::move(*k);
  return {};
}

Result<SharedSecret> PinManager::shared_secret_for(const crypto::P256PublicKey& platform_key) {
  if (!ka_) {
    return std::unexpected(Status::Other);
  }
  auto z = ka_->shared_secret_x(platform_key);
  if (!z) {
    return std::unexpected(Status::InvalidParameter);
  }
  auto ss = derive_shared_secret(crypto_, *z);
  OPENSSL_cleanse(z->data(), z->size());
  return ss;
}

Result<std::vector<std::uint8_t>> PinManager::get_retries() {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(3), Writer::encode_uint(retries()));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

Result<std::vector<std::uint8_t>> PinManager::get_key_agreement() {
  if (!ka_) {
    return std::unexpected(Status::Other);
  }
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(1), encode_cose_ecdh(ka_->pub()));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

Result<std::array<std::uint8_t, 16>> PinManager::pin_from_padded(
    const SharedSecret& ss, std::span<const std::uint8_t> new_pin_enc) {
  auto padded = pin2_decrypt(crypto_, ss, new_pin_enc);
  if (!padded) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (padded->size() < 64) {
    OPENSSL_cleanse(padded->data(), padded->size());
    return std::unexpected(Status::PinPolicyViolation);
  }
  std::size_t len = 0;
  while (len < padded->size() && (*padded)[len] != 0) {
    ++len;
  }
  // Count UTF-8 code points for the 4..63 policy.
  std::size_t cps = 0;
  for (std::size_t i = 0; i < len; ++i) {
    if (((*padded)[i] & 0xC0) != 0x80) {
      ++cps;
    }
  }
  if (len == 0 || cps < 4 || cps > 63 || len > 63) {
    OPENSSL_cleanse(padded->data(), padded->size());
    return std::unexpected(Status::PinPolicyViolation);
  }
  const auto digest = crypto_.sha256(std::span<const std::uint8_t>(padded->data(), len));
  OPENSSL_cleanse(padded->data(), padded->size());
  std::array<std::uint8_t, 16> out{};
  std::memcpy(out.data(), digest.data(), 16);
  return out;
}

Result<void> PinManager::check_pin_hash(const SharedSecret& ss,
                                        std::span<const std::uint8_t> pin_hash_enc,
                                        CancelToken& cancel) {
  auto pin = store_.pin();
  if (!pin.hash) {
    return std::unexpected(Status::PinNotSet);
  }
  if (pin.retries == 0) {
    ++pin_block_;
    return std::unexpected(Status::PinBlocked);
  }
  // Failure delay after 3 consecutive misses (keepalives keep the host waiting).
  const auto delay = failure_delay(consecutive_failures_, failure_delay_base_);
  if (delay.count() > 0) {
    const auto until = std::chrono::steady_clock::now() + delay;
    while (std::chrono::steady_clock::now() < until) {
      if (cancel.is_cancelled()) {
        return std::unexpected(Status::KeepaliveCancel);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  auto got = pin2_decrypt(crypto_, ss, pin_hash_enc);
  if (!got || got->size() != 16) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  const bool ok = crypto_.consttime_equal(*got, *pin.hash);
  OPENSSL_cleanse(got->data(), got->size());
  if (!ok) {
    ++pin_fail_;
    ++consecutive_failures_;
    pin.retries = static_cast<std::uint8_t>(pin.retries - 1);
    (void)store_.set_pin(pin);
    (void)regenerate_key_agreement();  // spec: new key agreement after a failure
    log::warn("pin_invalid", {{"retries", std::to_string(pin.retries)}});
    if (pin.retries == 0) {
      ++pin_block_;
      return std::unexpected(Status::PinBlocked);
    }
    return std::unexpected(Status::PinInvalid);
  }
  consecutive_failures_ = 0;
  if (pin.retries != kMaxRetries) {
    pin.retries = kMaxRetries;
    (void)store_.set_pin(pin);
  }
  return {};
}

Result<std::vector<std::uint8_t>> PinManager::set_pin(const crypto::P256PublicKey& platform_key,
                                                      std::span<const std::uint8_t> new_pin_enc,
                                                      std::span<const std::uint8_t> pin_auth,
                                                      CancelToken& cancel) {
  (void)cancel;
  if (pin_set()) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto ss = shared_secret_for(platform_key);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  auto mac = pin2_authenticate(crypto_, ss->hmac_key, new_pin_enc);
  if (!mac || !crypto_.consttime_equal(*mac, pin_auth)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto hash = pin_from_padded(*ss, new_pin_enc);
  if (!hash) {
    return std::unexpected(hash.error());
  }
  store::PinState st;
  st.hash = *hash;
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  OPENSSL_cleanse(hash->data(), hash->size());
  consecutive_failures_ = 0;
  log::info("pin_set");
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> PinManager::change_pin(
    const crypto::P256PublicKey& platform_key, std::span<const std::uint8_t> pin_hash_enc,
    std::span<const std::uint8_t> new_pin_enc, std::span<const std::uint8_t> pin_auth,
    CancelToken& cancel) {
  auto ss = shared_secret_for(platform_key);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  std::vector<std::uint8_t> msg(new_pin_enc.begin(), new_pin_enc.end());
  msg.insert(msg.end(), pin_hash_enc.begin(), pin_hash_enc.end());
  auto mac = pin2_authenticate(crypto_, ss->hmac_key, msg);
  if (!mac || !crypto_.consttime_equal(*mac, pin_auth)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (auto c = check_pin_hash(*ss, pin_hash_enc, cancel); !c) {
    return std::unexpected(c.error());
  }
  auto hash = pin_from_padded(*ss, new_pin_enc);
  if (!hash) {
    return std::unexpected(hash.error());
  }
  store::PinState st;
  st.hash = *hash;
  st.retries = kMaxRetries;
  if (auto r = store_.set_pin(st); !r) {
    return std::unexpected(Status::Other);
  }
  OPENSSL_cleanse(hash->data(), hash->size());
  invalidate_token();  // K23: PIN change invalidates outstanding tokens
  log::info("pin_changed");
  return std::vector<std::uint8_t>{};
}

Result<std::vector<std::uint8_t>> PinManager::get_token(const crypto::P256PublicKey& platform_key,
                                                        std::span<const std::uint8_t> pin_hash_enc,
                                                        std::uint8_t permissions,
                                                        std::optional<std::string> rp_id,
                                                        CancelToken& cancel) {
  auto ss = shared_secret_for(platform_key);
  if (!ss) {
    return std::unexpected(ss.error());
  }
  if (auto c = check_pin_hash(*ss, pin_hash_enc, cancel); !c) {
    return std::unexpected(c.error());
  }
  PinUvAuthToken t;
  if (!crypto_.random(t.bytes)) {
    return std::unexpected(Status::Other);
  }
  t.permissions = permissions;
  t.permissions_rp_id = std::move(rp_id);
  t.expiry = std::chrono::steady_clock::now() + token_idle_timeout_;
  invalidate_token();
  token_ = t;
  OPENSSL_cleanse(t.bytes.data(), t.bytes.size());
  auto enc = pin2_encrypt(crypto_, *ss, token_->bytes);
  if (!enc) {
    invalidate_token();
    return std::unexpected(Status::Other);
  }
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(*enc));
  Writer w;
  w.write_map(std::move(m));
  log::info("pin_token_issued", {{"perms", std::to_string(permissions)},
                                 {"rp", token_->permissions_rp_id.value_or("")}});
  return w.finish();
}

Result<bool> PinManager::verify(std::span<const std::uint8_t> param, std::uint64_t protocol,
                                std::span<const std::uint8_t, 32> client_data_hash,
                                std::uint8_t permission, const std::string& rp_id) {
  if (protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (!token_) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if (std::chrono::steady_clock::now() > token_->expiry) {
    log::info("pin_token_expired");
    invalidate_token();
    return std::unexpected(Status::PinAuthInvalid);
  }
  auto mac = pin2_authenticate(crypto_, token_->bytes, client_data_hash);
  if (!mac || !crypto_.consttime_equal(*mac, param)) {
    return std::unexpected(Status::PinAuthInvalid);
  }
  if ((token_->permissions & permission) == 0) {
    return std::unexpected(Status::UnauthorizedPermission);
  }
  if (token_->permissions_rp_id) {
    if (*token_->permissions_rp_id != rp_id) {
      return std::unexpected(Status::PinAuthInvalid);
    }
  } else {
    token_->permissions_rp_id = rp_id;  // bind on first use (getPinToken 0x05)
  }
  token_->expiry = std::chrono::steady_clock::now() + token_idle_timeout_;  // not one-shot
  return true;
}

Result<std::vector<std::uint8_t>> PinManager::handle(std::span<const std::uint8_t> body,
                                                     CancelToken& cancel) {
  Reader r(body);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  std::optional<std::uint64_t> protocol;
  std::optional<std::uint64_t> sub;
  std::optional<crypto::P256PublicKey> key_agreement;
  std::optional<std::vector<std::uint8_t>> pin_auth;
  std::optional<std::vector<std::uint8_t>> new_pin_enc;
  std::optional<std::vector<std::uint8_t>> pin_hash_enc;
  std::optional<std::uint64_t> permissions;
  std::optional<std::string> rp_id;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = read_int_key(r);
    if (!k) {
      return std::unexpected(k.error());
    }
    switch (*k) {
      case 0x01: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        protocol = *v;
        break;
      }
      case 0x02: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        sub = *v;
        break;
      }
      case 0x03: {
        auto v = parse_cose_p256(r);
        if (!v) return std::unexpected(v.error());
        key_agreement = *v;
        break;
      }
      case 0x04: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        pin_auth = *v;
        break;
      }
      case 0x05: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        new_pin_enc = *v;
        break;
      }
      case 0x06: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        pin_hash_enc = *v;
        break;
      }
      case 0x09: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        permissions = *v;
        break;
      }
      case 0x0A: {
        auto v = r.tstr();
        if (!v) return std::unexpected(v.error());
        rp_id = *v;
        break;
      }
      default:
        if (auto s = r.skip(); !s) return std::unexpected(s.error());
        break;
    }
  }
  if (!sub) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*sub == kSubGetRetries) {
    return get_retries();
  }
  if (*sub == kSubGetTokenUsingUv || *sub == kSubGetUvRetries) {
    return std::unexpected(Status::InvalidSubcommand);  // no built-in UV
  }
  if (!protocol) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  switch (*sub) {
    case kSubGetKeyAgreement:
      return get_key_agreement();
    case kSubSetPin:
      if (!key_agreement || !new_pin_enc || !pin_auth) {
        return std::unexpected(Status::MissingParameter);
      }
      return set_pin(*key_agreement, *new_pin_enc, *pin_auth, cancel);
    case kSubChangePin:
      if (!key_agreement || !new_pin_enc || !pin_hash_enc || !pin_auth) {
        return std::unexpected(Status::MissingParameter);
      }
      return change_pin(*key_agreement, *pin_hash_enc, *new_pin_enc, *pin_auth, cancel);
    case kSubGetPinToken:
      if (!key_agreement || !pin_hash_enc) {
        return std::unexpected(Status::MissingParameter);
      }
      return get_token(*key_agreement, *pin_hash_enc, kPermMc | kPermGa, std::nullopt, cancel);
    case kSubGetTokenUsingPin: {
      if (!key_agreement || !pin_hash_enc || !permissions) {
        return std::unexpected(Status::MissingParameter);
      }
      if (*permissions == 0 || *permissions > 0xFF) {
        return std::unexpected(Status::InvalidParameter);
      }
      const auto perms = static_cast<std::uint8_t>(*permissions);
      if ((perms & ~kSupportedPerms) != 0) {
        return std::unexpected(Status::UnauthorizedPermission);
      }
      if ((perms & kPermMc) != 0 && !rp_id) {
        return std::unexpected(Status::UnauthorizedPermission);
      }
      return get_token(*key_agreement, *pin_hash_enc, perms, rp_id, cancel);
    }
    default:
      return std::unexpected(Status::InvalidSubcommand);
  }
}

}  // namespace swpk::ctap::detail
