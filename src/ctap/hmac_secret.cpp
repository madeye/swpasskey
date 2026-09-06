// hmac-secret extension, CTAP 2.1 dual credRandom (DESIGN.md "hmac-secret").
#include "ctap_internal.hpp"
#include "pin_state.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <cstring>

namespace swpk::ctap {

crypto::KeyBackend* Authenticator::backend_for(crypto::BackendKind kind) {
  if (kind == crypto::BackendKind::Software) {
    return &software_;
  }
  if (primary_.kind() == kind) {
    return &primary_;
  }
  return nullptr;
}

Result<std::vector<std::uint8_t>> Authenticator::hmac_secret_output(
    const store::Credential& cred, const detail::ExtensionsIn& ext, bool uv) {
  if (!ext.hmac_key_agreement.has_value() || ext.hmac_salt_enc.empty() ||
      ext.hmac_salt_auth.empty()) {
    return std::unexpected(Status::MissingParameter);
  }
  if (ext.hmac_pin_protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  auto ss = pin_->shared_secret_for(*ext.hmac_key_agreement);
  if (!ss) {
    return std::unexpected(Status::InvalidParameter);
  }
  auto mac = detail::pin2_authenticate(crypto_, ss->hmac_key, ext.hmac_salt_enc);
  if (!mac || !crypto_.consttime_equal(*mac, ext.hmac_salt_auth)) {
    return std::unexpected(Status::ExtensionFirst);
  }
  auto salts = detail::pin2_decrypt(crypto_, *ss, ext.hmac_salt_enc);
  if (!salts || (salts->size() != 32 && salts->size() != 64)) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (cred.cred_random.empty()) {
    return std::unexpected(Status::UnsupportedExtension);  // legacy row without credRandom
  }
  auto* be = backend_for(cred.backend);
  if (be == nullptr) {
    return std::unexpected(Status::InvalidCredential);
  }
  auto cr = be->unwrap_secret(cred.cred_random);
  if (!cr || cr->size() != 64) {
    log::error("cred_random_unwrap_failed", {{"rp", cred.rp_id}});
    return std::unexpected(Status::Other);
  }
  // CredRandomWithUV || CredRandomWithoutUV — select by the UV flag actually set.
  const auto sel = std::span<const std::uint8_t>(*cr).subspan(uv ? 0 : 32, 32);
  std::vector<std::uint8_t> out;
  for (std::size_t off = 0; off < salts->size(); off += 32) {
    auto h = crypto_.hmac_sha256(sel, std::span<const std::uint8_t>(*salts).subspan(off, 32));
    if (!h) {
      OPENSSL_cleanse(cr->data(), cr->size());
      return std::unexpected(Status::Other);
    }
    out.insert(out.end(), h->begin(), h->end());
  }
  OPENSSL_cleanse(cr->data(), cr->size());
  OPENSSL_cleanse(salts->data(), salts->size());
  auto enc = detail::pin2_encrypt(crypto_, *ss, out);
  OPENSSL_cleanse(out.data(), out.size());
  if (!enc) {
    return std::unexpected(Status::Other);
  }
  return enc;
}

}  // namespace swpk::ctap
