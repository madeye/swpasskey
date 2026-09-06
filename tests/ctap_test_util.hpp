#pragma once

#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/ui/presence.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace swpk::test {

using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;
using cbor::Writer;

inline std::vector<std::uint8_t> bytes(std::initializer_list<int> v) {
  std::vector<std::uint8_t> out;
  for (int b : v) out.push_back(static_cast<std::uint8_t>(b));
  return out;
}

inline std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

// ---- presences ---------------------------------------------------------------
class ScriptedPresence final : public ui::Presence {
public:
  ui::Decision next{ui::Decision::Allow};
  int calls{0};
  std::vector<ui::PresenceRequest> seen;
  ui::Decision confirm(const ui::PresenceRequest& r, ctap::CancelToken& c,
                       std::chrono::milliseconds) override {
    ++calls;
    seen.push_back(r);
    if (c.is_cancelled()) return ui::Decision::Cancelled;
    return next;
  }
  const char* name() const override { return "scripted"; }
};

// ---- fake hardware backend --------------------------------------------------
// Behaves like a TPM/SE from the authenticator's point of view: opaque handle,
// no scalar in the store row, scalars kept in an in-process map.
class FakeHwBackend final : public crypto::KeyBackend {
public:
  explicit FakeHwBackend(crypto::BackendKind kind = crypto::BackendKind::Tpm2) : kind_(kind) {}

  class Key final : public crypto::SigningKey {
  public:
    Key(std::unique_ptr<crypto::SigningKey> inner, std::vector<std::uint8_t> handle,
        crypto::BackendKind kind)
        : inner_(std::move(inner)), handle_(std::move(handle)), kind_(kind) {}
    crypto::BackendKind kind() const override { return kind_; }
    crypto::P256PublicKey pub() const override { return inner_->pub(); }
    Result<std::vector<std::uint8_t>> sign_der(std::span<const std::uint8_t> m) const override {
      return inner_->sign_der(m);
    }
    std::vector<std::uint8_t> persist_handle() const override { return handle_; }

  private:
    std::unique_ptr<crypto::SigningKey> inner_;
    std::vector<std::uint8_t> handle_;
    crypto::BackendKind kind_;
  };

  crypto::BackendKind kind() const override { return kind_; }

  Result<std::unique_ptr<crypto::SigningKey>> generate() override {
    auto k = sw_.generate();
    if (!k) return std::unexpected(k.error());
    auto sc = crypto::SoftwareKeyBackend::export_scalar_for_store(**k);
    if (!sc) return std::unexpected(sc.error());
    std::vector<std::uint8_t> handle = {'h', static_cast<std::uint8_t>(next_++)};
    scalars_[handle] = *sc;
    return std::make_unique<Key>(std::move(*k), handle, kind_);
  }
  Result<std::unique_ptr<crypto::SigningKey>> load(std::span<const std::uint8_t> handle,
                                                   const crypto::P256PublicKey& pub) override {
    ++loads;
    auto it = scalars_.find(std::vector<std::uint8_t>(handle.begin(), handle.end()));
    if (it == scalars_.end()) return std::unexpected(Status::InvalidCredential);
    auto k = sw_.load(it->second, pub);
    if (!k) return std::unexpected(k.error());
    return std::make_unique<Key>(std::move(*k), std::vector<std::uint8_t>(handle.begin(), handle.end()), kind_);
  }
  Result<void> destroy(std::span<const std::uint8_t> handle) override {
    ++destroys;
    scalars_.erase(std::vector<std::uint8_t>(handle.begin(), handle.end()));
    return {};
  }
  Result<std::vector<std::uint8_t>> wrap_secret(std::span<const std::uint8_t> s) override {
    std::vector<std::uint8_t> out = {'W'};
    out.insert(out.end(), s.begin(), s.end());
    return out;
  }
  Result<std::vector<std::uint8_t>> unwrap_secret(std::span<const std::uint8_t> w) override {
    if (w.empty() || w[0] != 'W') return std::unexpected(Status::Other);
    return std::vector<std::uint8_t>(w.begin() + 1, w.end());
  }

  int loads{0};
  int destroys{0};

private:
  crypto::BackendKind kind_;
  crypto::SoftwareKeyBackend sw_;
  std::map<std::vector<std::uint8_t>, std::array<std::uint8_t, 32>> scalars_;
  std::uint8_t next_{1};
};

// ---- request builders --------------------------------------------------------
struct MakeCredOpts {
  std::string rp_id{"example.com"};
  std::string rp_name{"Example"};
  std::vector<std::uint8_t> user_id{bytes({1, 2, 3, 4})};
  std::string user_name{"alice"};
  std::string user_display{"Alice"};
  std::vector<std::vector<std::uint8_t>> exclude;
  std::optional<bool> rk, up, uv;
  std::optional<std::uint64_t> cred_protect;
  bool hmac_create_secret{false};
  bool enterprise{false};
  std::optional<std::vector<std::uint8_t>> pin_auth;
  std::optional<std::uint64_t> pin_protocol;
  int alg{-7};
  std::array<std::uint8_t, 32> client_data_hash{};
};

inline std::vector<std::uint8_t> make_cred_request(const MakeCredOpts& o) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(1), Writer::encode_bstr(o.client_data_hash));
  {
    std::vector<Entry> rp;
    rp.emplace_back(Writer::encode_tstr("id"), Writer::encode_tstr(o.rp_id));
    rp.emplace_back(Writer::encode_tstr("name"), Writer::encode_tstr(o.rp_name));
    Writer w;
    w.write_map(std::move(rp));
    m.emplace_back(Writer::encode_uint(2), w.finish());
  }
  {
    std::vector<Entry> u;
    u.emplace_back(Writer::encode_tstr("id"), Writer::encode_bstr(o.user_id));
    u.emplace_back(Writer::encode_tstr("name"), Writer::encode_tstr(o.user_name));
    u.emplace_back(Writer::encode_tstr("displayName"), Writer::encode_tstr(o.user_display));
    Writer w;
    w.write_map(std::move(u));
    m.emplace_back(Writer::encode_uint(3), w.finish());
  }
  {
    Writer w;
    w.write_array_header(1);
    std::vector<Entry> p;
    p.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(o.alg));
    p.emplace_back(Writer::encode_tstr("type"), Writer::encode_tstr("public-key"));
    Writer pw;
    pw.write_map(std::move(p));
    w.write_raw(pw.finish());
    m.emplace_back(Writer::encode_uint(4), w.finish());
  }
  if (!o.exclude.empty()) {
    Writer w;
    w.write_array_header(o.exclude.size());
    for (const auto& id : o.exclude) {
      std::vector<Entry> d;
      d.emplace_back(Writer::encode_tstr("id"), Writer::encode_bstr(id));
      d.emplace_back(Writer::encode_tstr("type"), Writer::encode_tstr("public-key"));
      Writer dw;
      dw.write_map(std::move(d));
      w.write_raw(dw.finish());
    }
    m.emplace_back(Writer::encode_uint(5), w.finish());
  }
  if (o.cred_protect || o.hmac_create_secret) {
    std::vector<Entry> e;
    if (o.cred_protect) e.emplace_back(Writer::encode_tstr("credProtect"), Writer::encode_uint(*o.cred_protect));
    if (o.hmac_create_secret) e.emplace_back(Writer::encode_tstr("hmac-secret"), Writer::encode_bool(true));
    Writer w;
    w.write_map(std::move(e));
    m.emplace_back(Writer::encode_uint(6), w.finish());
  }
  if (o.rk || o.up || o.uv) {
    std::vector<Entry> e;
    if (o.rk) e.emplace_back(Writer::encode_tstr("rk"), Writer::encode_bool(*o.rk));
    if (o.up) e.emplace_back(Writer::encode_tstr("up"), Writer::encode_bool(*o.up));
    if (o.uv) e.emplace_back(Writer::encode_tstr("uv"), Writer::encode_bool(*o.uv));
    Writer w;
    w.write_map(std::move(e));
    m.emplace_back(Writer::encode_uint(7), w.finish());
  }
  if (o.pin_auth) m.emplace_back(Writer::encode_uint(8), Writer::encode_bstr(*o.pin_auth));
  if (o.pin_protocol) m.emplace_back(Writer::encode_uint(9), Writer::encode_uint(*o.pin_protocol));
  if (o.enterprise) m.emplace_back(Writer::encode_uint(10), Writer::encode_bool(true));
  Writer w;
  w.write_map(std::move(m));
  auto body = w.finish();
  body.insert(body.begin(), ctap::kCmdMakeCredential);
  return body;
}

struct GetAssertOpts {
  std::string rp_id{"example.com"};
  std::array<std::uint8_t, 32> client_data_hash{};
  std::optional<std::vector<std::vector<std::uint8_t>>> allow;
  std::optional<bool> up, uv;
  std::optional<std::vector<std::uint8_t>> pin_auth;
  std::optional<std::uint64_t> pin_protocol;
  std::optional<std::vector<std::uint8_t>> hmac_secret_ext;  // pre-encoded map (PR10)
};

inline std::vector<std::uint8_t> get_assert_request(const GetAssertOpts& o) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_uint(1), Writer::encode_tstr(o.rp_id));
  m.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(o.client_data_hash));
  if (o.allow) {
    Writer w;
    w.write_array_header(o.allow->size());
    for (const auto& id : *o.allow) {
      std::vector<Entry> d;
      d.emplace_back(Writer::encode_tstr("id"), Writer::encode_bstr(id));
      d.emplace_back(Writer::encode_tstr("type"), Writer::encode_tstr("public-key"));
      Writer dw;
      dw.write_map(std::move(d));
      w.write_raw(dw.finish());
    }
    m.emplace_back(Writer::encode_uint(3), w.finish());
  }
  if (o.hmac_secret_ext) {
    std::vector<Entry> e;
    e.emplace_back(Writer::encode_tstr("hmac-secret"), *o.hmac_secret_ext);
    Writer w;
    w.write_map(std::move(e));
    m.emplace_back(Writer::encode_uint(4), w.finish());
  }
  if (o.up || o.uv) {
    std::vector<Entry> e;
    if (o.up) e.emplace_back(Writer::encode_tstr("up"), Writer::encode_bool(*o.up));
    if (o.uv) e.emplace_back(Writer::encode_tstr("uv"), Writer::encode_bool(*o.uv));
    Writer w;
    w.write_map(std::move(e));
    m.emplace_back(Writer::encode_uint(5), w.finish());
  }
  if (o.pin_auth) m.emplace_back(Writer::encode_uint(6), Writer::encode_bstr(*o.pin_auth));
  if (o.pin_protocol) m.emplace_back(Writer::encode_uint(7), Writer::encode_uint(*o.pin_protocol));
  Writer w;
  w.write_map(std::move(m));
  auto body = w.finish();
  body.insert(body.begin(), ctap::kCmdGetAssertion);
  return body;
}

// ---- response decoding -----------------------------------------------------
// Splits a top-level integer-keyed map into key -> raw encoded value.
inline std::map<std::int64_t, std::vector<std::uint8_t>> split_int_map(
    std::span<const std::uint8_t> enc) {
  std::map<std::int64_t, std::vector<std::uint8_t>> out;
  cbor::Reader r(enc);
  auto n = r.map();
  if (!n) return out;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.integer();
    if (!k) return out;
    const auto start = r.offset();
    if (!r.skip()) return out;
    out[*k] = std::vector<std::uint8_t>(enc.begin() + static_cast<std::ptrdiff_t>(start),
                                        enc.begin() + static_cast<std::ptrdiff_t>(r.offset()));
  }
  return out;
}

inline std::map<std::string, std::vector<std::uint8_t>> split_text_map(
    std::span<const std::uint8_t> enc) {
  std::map<std::string, std::vector<std::uint8_t>> out;
  cbor::Reader r(enc);
  auto n = r.map();
  if (!n) return out;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) return out;
    const auto start = r.offset();
    if (!r.skip()) return out;
    out[*k] = std::vector<std::uint8_t>(enc.begin() + static_cast<std::ptrdiff_t>(start),
                                        enc.begin() + static_cast<std::ptrdiff_t>(r.offset()));
  }
  return out;
}

inline std::vector<std::uint8_t> as_bstr(std::span<const std::uint8_t> enc) {
  cbor::Reader r(enc);
  auto b = r.bstr();
  return b ? *b : std::vector<std::uint8_t>{};
}

struct ParsedAuthData {
  std::array<std::uint8_t, 32> rp_id_hash{};
  std::uint8_t flags{};
  std::uint32_t sign_count{};
  std::array<std::uint8_t, 16> aaguid{};
  std::vector<std::uint8_t> cred_id;
  crypto::P256PublicKey pub{};
  std::vector<std::uint8_t> extensions;
};

inline ParsedAuthData parse_auth_data(std::span<const std::uint8_t> ad) {
  ParsedAuthData p;
  std::memcpy(p.rp_id_hash.data(), ad.data(), 32);
  p.flags = ad[32];
  p.sign_count = (static_cast<std::uint32_t>(ad[33]) << 24) | (static_cast<std::uint32_t>(ad[34]) << 16) |
                 (static_cast<std::uint32_t>(ad[35]) << 8) | ad[36];
  std::size_t off = 37;
  if (p.flags & 0x40) {
    std::memcpy(p.aaguid.data(), ad.data() + off, 16);
    off += 16;
    const std::size_t len = (static_cast<std::size_t>(ad[off]) << 8) | ad[off + 1];
    off += 2;
    p.cred_id.assign(ad.begin() + static_cast<std::ptrdiff_t>(off), ad.begin() + static_cast<std::ptrdiff_t>(off + len));
    off += len;
    cbor::Reader r(ad.subspan(off));
    auto n = r.map();
    for (std::size_t i = 0; n && i < *n; ++i) {
      auto k = r.integer();
      if (!k) break;
      if (*k == -2 || *k == -3) {
        auto b = r.bstr();
        if (b && b->size() == 32) std::memcpy(*k == -2 ? p.pub.x.data() : p.pub.y.data(), b->data(), 32);
      } else {
        (void)r.skip();
      }
    }
    off += r.offset();
  }
  if (p.flags & 0x80) {
    p.extensions.assign(ad.begin() + static_cast<std::ptrdiff_t>(off), ad.end());
  }
  return p;
}

inline bool verify_es256(const crypto::P256PublicKey& pub, std::span<const std::uint8_t> msg,
                         std::span<const std::uint8_t> der) {
  std::uint8_t enc[65];
  enc[0] = 0x04;
  std::memcpy(enc + 1, pub.x.data(), 32);
  std::memcpy(enc + 33, pub.y.data(), 32);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("P-256"), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, enc, sizeof(enc)),
      OSSL_PARAM_construct_end()};
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  bool ok = ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
  EVP_PKEY_CTX_free(ctx);
  if (!ok) return false;
  EVP_MD_CTX* mctx = EVP_MD_CTX_new();
  ok = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
       EVP_DigestVerify(mctx, der.data(), der.size(), msg.data(), msg.size()) == 1;
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_free(pkey);
  return ok;
}

// ---- rig ------------------------------------------------------------------
struct Rig {
  crypto::Provider crypto;
  crypto::SoftwareKeyBackend software;
  std::unique_ptr<crypto::KeyBackend> hw;  // optional primary
  std::unique_ptr<store::CredentialStore> store = store::CredentialStore::open_memory();
  ScriptedPresence presence;
  std::unique_ptr<ctap::Authenticator> auth;
  ctap::CancelToken tok;

  explicit Rig(bool with_hw = false) {
    if (with_hw) hw = std::make_unique<FakeHwBackend>();
    ctap::AuthenticatorConfig cfg;
    cfg.up_timeout = std::chrono::milliseconds(200);
    auth = std::make_unique<ctap::Authenticator>(cfg, crypto, hw ? *hw : software, software, *store, presence);
  }

  Result<std::vector<std::uint8_t>> call(const std::vector<std::uint8_t>& req) {
    tok.reset();
    return auth->handle_cbor(req, tok);
  }

  // Registers a credential and returns its id.
  std::vector<std::uint8_t> register_cred(MakeCredOpts o = {}) {
    auto r = call(make_cred_request(o));
    if (!r) return {};
    auto m = split_int_map(*r);
    auto ad = parse_auth_data(as_bstr(m[2]));
    return ad.cred_id;
  }
};

}  // namespace swpk::test
