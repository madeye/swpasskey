// authenticatorMakeCredential (0x01) — DESIGN.md "authenticatorMakeCredential".
#include "ctap_internal.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <cstring>

namespace swpk::ctap {
namespace {

using cbor::Reader;
using cbor::Writer;
using detail::Entry;

struct MakeCredentialRequest {
  std::array<std::uint8_t, 32> client_data_hash{};
  bool have_client_data_hash{false};
  std::optional<detail::RpEntity> rp;
  std::optional<detail::UserEntity> user;
  std::optional<bool> has_es256;
  std::vector<detail::PubKeyCredDescriptor> exclude_list;
  detail::ExtensionsIn ext;
  bool have_ext{false};
  detail::Options options;
  std::optional<std::vector<std::uint8_t>> pin_uv_auth_param;
  std::optional<std::uint64_t> pin_uv_auth_protocol;
  bool enterprise_attestation{false};
};

Result<MakeCredentialRequest> parse(std::span<const std::uint8_t> body) {
  MakeCredentialRequest q;
  Reader r(body);
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = detail::read_int_key(r);
    if (!k) {
      return std::unexpected(k.error());
    }
    switch (*k) {
      case 0x01: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        if (v->size() != 32) return std::unexpected(Status::InvalidParameter);
        std::memcpy(q.client_data_hash.data(), v->data(), 32);
        q.have_client_data_hash = true;
        break;
      }
      case 0x02: {
        auto v = detail::parse_rp(r);
        if (!v) return std::unexpected(v.error());
        q.rp = *v;
        break;
      }
      case 0x03: {
        auto v = detail::parse_user(r);
        if (!v) return std::unexpected(v.error());
        q.user = *v;
        break;
      }
      case 0x04: {
        auto v = detail::parse_pub_key_cred_params_has_es256(r);
        if (!v) return std::unexpected(v.error());
        q.has_es256 = *v;
        break;
      }
      case 0x05: {
        auto v = detail::parse_descriptor_list(r);
        if (!v) return std::unexpected(v.error());
        q.exclude_list = std::move(*v);
        break;
      }
      case 0x06: {
        auto v = detail::parse_extensions(r);
        if (!v) return std::unexpected(v.error());
        q.ext = *v;
        q.have_ext = true;
        break;
      }
      case 0x07: {
        auto v = detail::parse_options(r);
        if (!v) return std::unexpected(v.error());
        q.options = *v;
        break;
      }
      case 0x08: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_param = *v;
        break;
      }
      case 0x09: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_protocol = *v;
        break;
      }
      case 0x0A: {
        auto v = r.boolean();
        if (!v) return std::unexpected(v.error());
        q.enterprise_attestation = true;
        break;
      }
      default:
        if (auto s = r.skip(); !s) return std::unexpected(s.error());
        break;
    }
  }
  if (!q.have_client_data_hash || !q.rp || !q.user || !q.has_es256.has_value()) {
    return std::unexpected(Status::MissingParameter);
  }
  return q;
}

}  // namespace

Result<std::vector<std::uint8_t>> Authenticator::cmd_make_credential(
    std::span<const std::uint8_t> body, CancelToken& cancel) {
  auto fail = [this](Status s) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.make_cred_err;
    return std::unexpected(s);
  };

  auto q = parse(body);
  if (!q) {
    return fail(q.error());
  }
  if (q->enterprise_attestation) {
    return fail(Status::InvalidParameter);
  }
  if (q->rp->id.empty() || q->rp->id.size() > 255) {
    return fail(Status::InvalidParameter);
  }
  if (q->user->id.size() > 64) {
    return fail(Status::LimitExceeded);
  }
  if (!*q->has_es256) {
    return fail(Status::UnsupportedAlgorithm);
  }
  // Option-byte policy (DESIGN.md).
  if (q->options.up.has_value() && !*q->options.up) {
    return fail(Status::InvalidOption);
  }
  if (q->options.rk.has_value() && !*q->options.rk) {
    return fail(Status::UnsupportedOption);
  }
  if (q->options.uv.has_value() && *q->options.uv) {
    return fail(Status::InvalidOption);
  }
  if (q->ext.cred_protect.has_value() && *q->ext.cred_protect > 1) {
    return fail(Status::UnsupportedExtension);  // K27: fail closed
  }

  const auto rp_id_hash = crypto_.sha256(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(q->rp->id.data()),
                                    q->rp->id.size()));

  // PIN / UV (PR9): verify token with `mc` permission when present.
  PinAuthIn pin_in;
  pin_in.param = q->pin_uv_auth_param;
  pin_in.protocol = q->pin_uv_auth_protocol;
  auto uv = check_pin_auth(pin_in, q->client_data_hash, 0x01, q->rp->id, true);
  if (!uv) {
    return fail(uv.error());
  }

  // excludeList lookup happens before UP but is only reported after it.
  bool excluded = false;
  for (const auto& d : q->exclude_list) {
    if (d.type != "public-key") {
      continue;
    }
    if (store_.find(rp_id_hash, d.id).has_value()) {
      excluded = true;
      break;
    }
  }

  const std::string display = q->user->display_name.empty() ? q->user->name : q->user->display_name;
  const auto decision = confirm_up(ui::PresenceRequest::Kind::MakeCredential, q->rp->id, display,
                                   rp_id_hash, cancel);
  if (decision == ui::Decision::Cancelled) {
    return fail(Status::KeepaliveCancel);
  }
  if (excluded) {
    return fail(Status::CredentialExcluded);  // Allow, Deny and Timeout all land here
  }
  if (decision == ui::Decision::Deny) {
    return fail(Status::OperationDenied);
  }
  if (decision == ui::Decision::Timeout) {
    return fail(Status::UserActionTimeout);
  }
  if (store_.remaining() == 0) {
    return fail(Status::KeyStoreFull);
  }

  // Generate the credential key on the primary backend.
  auto key = primary_.generate();
  if (!key) {
    log::error("key_generate_failed", {{"backend", primary_backend_name()}});
    return fail(Status::Other);
  }
  store::Credential c;
  c.rp_id = q->rp->id;
  c.rp_id_hash = rp_id_hash;
  c.rp_name = q->rp->name;
  c.user_id = q->user->id;
  c.user_name = q->user->name;
  c.user_display = q->user->display_name;
  if (!crypto_.random(c.cred_id)) {
    return fail(Status::Other);
  }
  c.backend = (*key)->kind();
  c.pub = (*key)->pub();
  c.sign_count = 1;
  c.created_unix = now_unix();
  c.last_used_unix = c.created_unix;
  if (c.backend == crypto::BackendKind::Software) {
    auto sc = crypto::SoftwareKeyBackend::export_scalar_for_store(**key);
    if (!sc) {
      return fail(Status::Other);
    }
    c.priv.assign(sc->begin(), sc->end());
    OPENSSL_cleanse(sc->data(), sc->size());
  } else {
    c.handle = (*key)->persist_handle();
  }
  // CTAP 2.1 dual credRandom (UV || noUV), generated for every credential.
  {
    std::array<std::uint8_t, 64> cred_random{};
    if (!crypto_.random(cred_random)) {
      return fail(Status::Other);
    }
    auto wrapped = primary_.wrap_secret(cred_random);
    OPENSSL_cleanse(cred_random.data(), cred_random.size());
    if (!wrapped) {
      log::error("wrap_secret_failed", {{"backend", primary_backend_name()}});
      return fail(Status::Other);
    }
    c.cred_random = std::move(*wrapped);
  }

  // Persist before any success response leaves the worker.
  if (auto p = store_.put(c); !p) {
    (void)primary_.destroy(c.handle);
    return fail(p.error() == Status::KeyStoreFull ? Status::KeyStoreFull : Status::Other);
  }

  // authData
  std::uint8_t flags = detail::kFlagUp | detail::kFlagAt;
  if (*uv) {
    flags |= detail::kFlagUv;
  }
  std::vector<std::uint8_t> ext_out;
  if (q->ext.hmac_create_secret) {
    // PR10: {"hmac-secret": true} once advertised. Not emitted before then.
  }
  if (!ext_out.empty()) {
    flags |= detail::kFlagEd;
  }
  const auto att = detail::build_attested_credential_data(cfg_.aaguid, c.cred_id, c.pub);
  const auto auth_data = detail::build_auth_data(rp_id_hash, flags, c.sign_count, att, ext_out);

  // Packed self-attestation: sign(authData || clientDataHash) with the credential key.
  std::vector<std::uint8_t> to_sign(auth_data);
  to_sign.insert(to_sign.end(), q->client_data_hash.begin(), q->client_data_hash.end());
  auto sig = (*key)->sign_der(to_sign);
  if (!sig) {
    log::error("sign_failed", {{"backend", primary_backend_name()}});
    return fail(Status::Other);
  }

  std::vector<Entry> att_stmt;
  att_stmt.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(-7));
  att_stmt.emplace_back(Writer::encode_tstr("sig"), Writer::encode_bstr(*sig));
  Writer aw;
  aw.write_map(std::move(att_stmt));

  std::vector<Entry> resp;
  resp.emplace_back(Writer::encode_uint(1), Writer::encode_tstr("packed"));
  resp.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(auth_data));
  resp.emplace_back(Writer::encode_uint(3), aw.finish());
  Writer w;
  w.write_map(std::move(resp));

  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.make_cred_ok;
  }
  log::info("make_credential", {{"rp", c.rp_id}, {"key_backend", primary_backend_name()}});
  return w.finish();
}

}  // namespace swpk::ctap
