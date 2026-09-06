#include "swpasskey/store/credential.hpp"

#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

namespace swpk::store {
namespace {

using cbor::Reader;
using cbor::Writer;
using Entry = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;

bool same_id(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  return a.size() == b.size() && (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

std::vector<std::uint8_t> encode_credential(const Credential& c) {
  std::vector<Entry> m;
  auto put_b = [&](const char* k, std::span<const std::uint8_t> v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_bstr(v));
  };
  auto put_t = [&](const char* k, std::string_view v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_tstr(v));
  };
  auto put_u = [&](const char* k, std::uint64_t v) {
    m.emplace_back(Writer::encode_tstr(k), Writer::encode_uint(v));
  };
  put_t("rp_id", c.rp_id);
  put_b("rp_id_hash", c.rp_id_hash);
  put_t("rp_name", c.rp_name);
  put_b("user_id", c.user_id);
  put_t("user_name", c.user_name);
  put_t("user_display", c.user_display);
  put_b("cred_id", c.cred_id);
  put_u("backend", static_cast<std::uint64_t>(c.backend));
  put_b("handle", c.handle);
  put_b("priv", c.priv);
  put_b("pub_x", c.pub.x);
  put_b("pub_y", c.pub.y);
  put_u("sign_count", c.sign_count);
  put_u("created", c.created_unix);
  put_u("last_used", c.last_used_unix);
  put_b("cred_random", c.cred_random);
  m.emplace_back(Writer::encode_tstr("rk"), Writer::encode_bool(true));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

template <std::size_t N>
Result<void> read_fixed(Reader& r, std::array<std::uint8_t, N>& out) {
  auto b = r.bstr();
  if (!b) {
    return std::unexpected(b.error());
  }
  if (b->size() != N) {
    return std::unexpected(Status::InvalidCbor);
  }
  std::memcpy(out.data(), b->data(), N);
  return {};
}

Result<Credential> decode_credential(Reader& r) {
  Credential c;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto key = r.tstr();
    if (!key) {
      return std::unexpected(key.error());
    }
    const std::string& k = *key;
    Result<void> rc;
    if (k == "rp_id") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.rp_id = *v;
    } else if (k == "rp_id_hash") {
      rc = read_fixed(r, c.rp_id_hash);
    } else if (k == "rp_name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.rp_name = *v;
    } else if (k == "user_id") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.user_id = *v;
    } else if (k == "user_name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.user_name = *v;
    } else if (k == "user_display") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      c.user_display = *v;
    } else if (k == "cred_id") {
      rc = read_fixed(r, c.cred_id);
    } else if (k == "backend") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      if (*v > 2) return std::unexpected(Status::InvalidCbor);
      c.backend = static_cast<crypto::BackendKind>(*v);
    } else if (k == "handle") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.handle = *v;
    } else if (k == "priv") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.priv = *v;
    } else if (k == "pub_x") {
      rc = read_fixed(r, c.pub.x);
    } else if (k == "pub_y") {
      rc = read_fixed(r, c.pub.y);
    } else if (k == "sign_count") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.sign_count = static_cast<std::uint32_t>(*v);
    } else if (k == "created") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.created_unix = *v;
    } else if (k == "last_used") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      c.last_used_unix = *v;
    } else if (k == "cred_random") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      c.cred_random = *v;
    } else {
      rc = r.skip();
    }
    if (!rc) {
      return std::unexpected(rc.error());
    }
  }
  return c;
}

}  // namespace

Result<void> CredentialStore::validate(const Credential& c) {
  if (c.rp_id.empty() || c.rp_id.size() > 255) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (c.user_id.size() > 64) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (c.backend == crypto::BackendKind::Software) {
    if (!c.handle.empty() || c.priv.size() != 32) {
      return std::unexpected(Status::InvalidParameter);
    }
  } else {
    if (!c.priv.empty() || c.handle.empty()) {
      return std::unexpected(Status::InvalidParameter);
    }
  }
  return {};
}

std::unique_ptr<CredentialStore> CredentialStore::open_memory() {
  return std::unique_ptr<CredentialStore>(new CredentialStore());
}

Result<std::unique_ptr<CredentialStore>> CredentialStore::open_with(
    std::span<const std::uint8_t> plaintext, std::unique_ptr<Persister> persister) {
  std::unique_ptr<CredentialStore> s(new CredentialStore());
  s->persister_ = std::move(persister);
  if (!plaintext.empty()) {
    std::lock_guard<std::mutex> lk(s->mu_);
    if (auto r = s->load_locked(plaintext); !r) {
      return std::unexpected(r.error());
    }
  }
  return s;
}

Result<void> CredentialStore::load_locked(std::span<const std::uint8_t> plaintext) {
  Reader r(plaintext);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto key = r.tstr();
    if (!key) {
      return std::unexpected(key.error());
    }
    const std::string& k = *key;
    if (k == "aaguid") {
      std::array<std::uint8_t, 16> a{};
      if (auto rc = read_fixed(r, a); !rc) return rc;
    } else if (k == "install_id") {
      if (auto rc = read_fixed(r, install_id_); !rc) return rc;
    } else if (k == "serial") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      serial_ = *v;
    } else if (k == "pin") {
      auto pn = r.map();
      if (!pn) return std::unexpected(pn.error());
      for (std::size_t j = 0; j < *pn; ++j) {
        auto pk = r.tstr();
        if (!pk) return std::unexpected(pk.error());
        if (*pk == "hash") {
          std::array<std::uint8_t, 16> h{};
          if (auto rc = read_fixed(r, h); !rc) return rc;
          pin_.hash = h;
        } else if (*pk == "retries") {
          auto v = r.uint();
          if (!v) return std::unexpected(v.error());
          pin_.retries = static_cast<std::uint8_t>(*v);
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
    } else if (k == "tpm") {
      auto tn = r.map();
      if (!tn) return std::unexpected(tn.error());
      for (std::size_t j = 0; j < *tn; ++j) {
        auto tk = r.tstr();
        if (!tk) return std::unexpected(tk.error());
        if (*tk == "srk_unique_seed") {
          if (auto rc = read_fixed(r, tpm_.srk_unique_seed); !rc) return rc;
          tpm_.present = true;
        } else if (*tk == "object_auth") {
          if (auto rc = read_fixed(r, tpm_.object_auth); !rc) return rc;
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
    } else if (k == "u2f_attest") {
      auto un = r.map();
      if (!un) return std::unexpected(un.error());
      U2fAttestation a;
      for (std::size_t j = 0; j < *un; ++j) {
        auto uk = r.tstr();
        if (!uk) return std::unexpected(uk.error());
        if (*uk == "priv") {
          auto v = r.bstr();
          if (!v) return std::unexpected(v.error());
          a.priv = *v;
        } else if (*uk == "cert_der") {
          auto v = r.bstr();
          if (!v) return std::unexpected(v.error());
          a.cert_der = *v;
        } else if (auto rc = r.skip(); !rc) {
          return rc;
        }
      }
      u2f_ = std::move(a);
    } else if (k == "creds") {
      auto cn = r.array();
      if (!cn) return std::unexpected(cn.error());
      for (std::size_t j = 0; j < *cn; ++j) {
        auto c = decode_credential(r);
        if (!c) return std::unexpected(c.error());
        if (auto v = validate(*c); !v) {
          log::error("store_row_invalid", {{"rp", c->rp_id}});
          return std::unexpected(Status::Other);
        }
        creds_.push_back(std::move(*c));
      }
    } else if (auto rc = r.skip(); !rc) {
      return rc;
    }
  }
  return {};
}

std::vector<std::uint8_t> CredentialStore::serialize_locked() const {
  std::vector<Entry> top;
  top.emplace_back(Writer::encode_tstr("aaguid"), Writer::encode_bstr(kAaguid));
  top.emplace_back(Writer::encode_tstr("install_id"), Writer::encode_bstr(install_id_));
  top.emplace_back(Writer::encode_tstr("serial"), Writer::encode_tstr(serial_));
  {
    std::vector<Entry> pin;
    if (pin_.hash) {
      pin.emplace_back(Writer::encode_tstr("hash"), Writer::encode_bstr(*pin_.hash));
    }
    pin.emplace_back(Writer::encode_tstr("retries"), Writer::encode_uint(pin_.retries));
    Writer w;
    w.write_map(std::move(pin));
    top.emplace_back(Writer::encode_tstr("pin"), w.finish());
  }
  if (tpm_.present) {
    std::vector<Entry> t;
    t.emplace_back(Writer::encode_tstr("srk_unique_seed"),
                   Writer::encode_bstr(tpm_.srk_unique_seed));
    t.emplace_back(Writer::encode_tstr("object_auth"), Writer::encode_bstr(tpm_.object_auth));
    Writer w;
    w.write_map(std::move(t));
    top.emplace_back(Writer::encode_tstr("tpm"), w.finish());
  }
  if (u2f_) {
    std::vector<Entry> u;
    u.emplace_back(Writer::encode_tstr("priv"), Writer::encode_bstr(u2f_->priv));
    u.emplace_back(Writer::encode_tstr("cert_der"), Writer::encode_bstr(u2f_->cert_der));
    Writer w;
    w.write_map(std::move(u));
    top.emplace_back(Writer::encode_tstr("u2f_attest"), w.finish());
  }
  {
    Writer w;
    w.write_array_header(creds_.size());
    for (const auto& c : creds_) {
      w.write_raw(encode_credential(c));
    }
    top.emplace_back(Writer::encode_tstr("creds"), w.finish());
  }
  Writer w;
  w.write_map(std::move(top));
  return w.finish();
}

Result<void> CredentialStore::flush() {
  std::lock_guard<std::mutex> lk(mu_);
  return flush_locked();
}

std::vector<std::uint8_t> CredentialStore::serialize() const {
  std::lock_guard<std::mutex> lk(mu_);
  return serialize_locked();
}

Result<void> CredentialStore::flush_locked() {
  if (!persister_) {
    return {};
  }
  auto pt = serialize_locked();
  auto r = persister_->save(pt);
  OPENSSL_cleanse(pt.data(), pt.size());
  return r;
}

Result<void> CredentialStore::put(Credential c) {
  if (auto v = validate(c); !v) {
    return v;
  }
  std::lock_guard<std::mutex> lk(mu_);
  auto it = std::find_if(creds_.begin(), creds_.end(),
                         [&](const Credential& e) { return e.cred_id == c.cred_id; });
  if (it != creds_.end()) {
    *it = std::move(c);
    return flush_locked();
  }
  if (creds_.size() >= kMaxCredentials) {
    return std::unexpected(Status::KeyStoreFull);
  }
  creds_.push_back(std::move(c));
  return flush_locked();
}

std::vector<Credential> CredentialStore::find_by_rp(
    std::span<const std::uint8_t, 32> rp_id_hash) const {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<Credential> out;
  for (const auto& c : creds_) {
    if (same_id(c.rp_id_hash, rp_id_hash)) {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<Credential> CredentialStore::find(std::span<const std::uint8_t, 32> rp_id_hash,
                                                std::span<const std::uint8_t> cred_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& c : creds_) {
    if (same_id(c.rp_id_hash, rp_id_hash) && same_id(c.cred_id, cred_id)) {
      return c;
    }
  }
  return std::nullopt;
}

std::optional<Credential> CredentialStore::find_by_id(std::span<const std::uint8_t> cred_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& c : creds_) {
    if (same_id(c.cred_id, cred_id)) {
      return c;
    }
  }
  return std::nullopt;
}

Result<void> CredentialStore::update_count_and_used(std::span<const std::uint8_t> cred_id,
                                                    std::uint32_t new_count,
                                                    std::uint64_t now_unix) {
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& c : creds_) {
    if (same_id(c.cred_id, cred_id)) {
      c.sign_count = new_count;
      c.last_used_unix = now_unix;
      return flush_locked();
    }
  }
  return std::unexpected(Status::InvalidCredential);
}

Result<void> CredentialStore::erase(std::span<const std::uint8_t> cred_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = std::find_if(creds_.begin(), creds_.end(),
                         [&](const Credential& c) { return same_id(c.cred_id, cred_id); });
  if (it == creds_.end()) {
    return std::unexpected(Status::InvalidCredential);
  }
  OPENSSL_cleanse(it->priv.data(), it->priv.size());
  creds_.erase(it);
  return flush_locked();
}

std::vector<Credential> CredentialStore::all() const {
  std::lock_guard<std::mutex> lk(mu_);
  return creds_;
}

std::size_t CredentialStore::size() const {
  std::lock_guard<std::mutex> lk(mu_);
  return creds_.size();
}

std::size_t CredentialStore::remaining() const {
  std::lock_guard<std::mutex> lk(mu_);
  return kMaxCredentials - creds_.size();
}

std::array<std::size_t, 3> CredentialStore::count_by_backend() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::array<std::size_t, 3> out{};
  for (const auto& c : creds_) {
    ++out[static_cast<std::size_t>(c.backend)];
  }
  return out;
}

Result<void> CredentialStore::factory_reset(
    const std::function<void(const Credential&)>& destroy) {
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& c : creds_) {
    if (destroy) {
      destroy(c);
    }
    OPENSSL_cleanse(c.priv.data(), c.priv.size());
    OPENSSL_cleanse(c.cred_random.data(), c.cred_random.size());
  }
  creds_.clear();
  if (pin_.hash) {
    OPENSSL_cleanse(pin_.hash->data(), pin_.hash->size());
  }
  pin_ = PinState{};
  OPENSSL_cleanse(tpm_.srk_unique_seed.data(), tpm_.srk_unique_seed.size());
  OPENSSL_cleanse(tpm_.object_auth.data(), tpm_.object_auth.size());
  tpm_ = TpmState{};
  if (u2f_) {
    OPENSSL_cleanse(u2f_->priv.data(), u2f_->priv.size());
  }
  u2f_.reset();
  if (persister_) {
    if (auto r = persister_->reset(); !r) {
      return r;
    }
  }
  return flush_locked();
}

PinState CredentialStore::pin() const {
  std::lock_guard<std::mutex> lk(mu_);
  return pin_;
}

Result<void> CredentialStore::set_pin(PinState state) {
  std::lock_guard<std::mutex> lk(mu_);
  pin_ = state;
  return flush_locked();
}

Result<TpmState> CredentialStore::tpm_state_or_create(crypto::Provider& rng) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!tpm_.present) {
    if (!rng.random(tpm_.srk_unique_seed) || !rng.random(tpm_.object_auth)) {
      return std::unexpected(Status::Other);
    }
    tpm_.present = true;
    if (auto r = flush_locked(); !r) {
      return std::unexpected(r.error());
    }
  }
  return tpm_;
}

Result<void> CredentialStore::clear_tpm_state() {
  std::lock_guard<std::mutex> lk(mu_);
  OPENSSL_cleanse(tpm_.srk_unique_seed.data(), tpm_.srk_unique_seed.size());
  OPENSSL_cleanse(tpm_.object_auth.data(), tpm_.object_auth.size());
  tpm_ = TpmState{};
  return flush_locked();
}

std::optional<U2fAttestation> CredentialStore::u2f_attestation() const {
  std::lock_guard<std::mutex> lk(mu_);
  return u2f_;
}

Result<void> CredentialStore::set_u2f_attestation(U2fAttestation a) {
  std::lock_guard<std::mutex> lk(mu_);
  u2f_ = std::move(a);
  return flush_locked();
}

std::string CredentialStore::serial() const {
  std::lock_guard<std::mutex> lk(mu_);
  return serial_;
}

Result<void> CredentialStore::set_serial(std::string serial) {
  std::lock_guard<std::mutex> lk(mu_);
  if (serial_ == serial) {
    return {};
  }
  serial_ = std::move(serial);
  return flush_locked();
}

std::array<std::uint8_t, 16> CredentialStore::install_id() const {
  std::lock_guard<std::mutex> lk(mu_);
  return install_id_;
}

void CredentialStore::set_install_id(std::array<std::uint8_t, 16> id) {
  std::lock_guard<std::mutex> lk(mu_);
  install_id_ = id;
}

}  // namespace swpk::store
