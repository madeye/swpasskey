// Linux TPM 2.0 ESAPI KeyBackend (DESIGN.md "Linux TPM 2.0"). Compiled only
// when SWPASSKEY_TPM is set (tpm2-tss found). Also builds on macOS against a
// locally built tpm2-tss for swtpm testing.
#if defined(SWPASSKEY_TPM)

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"
#include "tpm2_templates.hpp"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/crypto.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <unistd.h>

namespace swpk::crypto {
namespace tpm2 {

Result<TPM2B_PUBLIC> primary_template(std::span<const std::uint8_t, 32> seed) {
  Provider p;
  const std::uint8_t salt[32] = {};
  const auto info = std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(kPrimaryUniqueInfo), sizeof(kPrimaryUniqueInfo) - 1);
  auto unique = p.hkdf_sha256(seed, salt, info);
  if (!unique) {
    return std::unexpected(unique.error());
  }
  TPM2B_PUBLIC pub{};
  pub.size = 0;
  auto& a = pub.publicArea;
  a.type = TPM2_ALG_ECC;
  a.nameAlg = TPM2_ALG_SHA256;
  a.objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                       TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                       TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA;
  a.authPolicy.size = 0;
  a.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
  a.parameters.eccDetail.symmetric.keyBits.aes = 128;
  a.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
  a.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
  a.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  a.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
  a.unique.ecc.x.size = 32;
  std::memcpy(a.unique.ecc.x.buffer, unique->data(), 32);
  a.unique.ecc.y.size = 0;
  return pub;
}

TPM2B_PUBLIC signing_child_template() {
  TPM2B_PUBLIC pub{};
  auto& a = pub.publicArea;
  a.type = TPM2_ALG_ECC;
  a.nameAlg = TPM2_ALG_SHA256;
  a.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                       TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                       TPMA_OBJECT_NODA;
  a.authPolicy.size = 0;
  a.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
  a.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
  a.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
  a.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  a.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
  a.unique.ecc.x.size = 0;
  a.unique.ecc.y.size = 0;
  return pub;
}

TPM2B_PUBLIC seal_template() {
  TPM2B_PUBLIC pub{};
  auto& a = pub.publicArea;
  a.type = TPM2_ALG_KEYEDHASH;
  a.nameAlg = TPM2_ALG_SHA256;
  // No SIGN/DECRYPT/RESTRICTED and, critically, no SENSITIVEDATAORIGIN:
  // the sensitive data is supplied by us.
  a.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_USERWITHAUTH |
                       TPMA_OBJECT_NODA;
  a.authPolicy.size = 0;
  a.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
  a.unique.keyedHash.size = 0;
  return pub;
}

Result<std::vector<std::uint8_t>> marshal_public(const TPM2B_PUBLIC& p) {
  std::vector<std::uint8_t> buf(sizeof(TPM2B_PUBLIC) + 16);
  std::size_t off = 0;
  if (Tss2_MU_TPM2B_PUBLIC_Marshal(&p, buf.data(), buf.size(), &off) != TSS2_RC_SUCCESS) {
    return std::unexpected(Status::Other);
  }
  buf.resize(off);
  return buf;
}

Result<std::vector<std::uint8_t>> marshal_private(const TPM2B_PRIVATE& p) {
  std::vector<std::uint8_t> buf(sizeof(TPM2B_PRIVATE) + 16);
  std::size_t off = 0;
  if (Tss2_MU_TPM2B_PRIVATE_Marshal(&p, buf.data(), buf.size(), &off) != TSS2_RC_SUCCESS) {
    return std::unexpected(Status::Other);
  }
  buf.resize(off);
  return buf;
}

Result<TPM2B_PUBLIC> unmarshal_public(std::span<const std::uint8_t> b) {
  TPM2B_PUBLIC p{};
  std::size_t off = 0;
  if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(b.data(), b.size(), &off, &p) != TSS2_RC_SUCCESS) {
    return std::unexpected(Status::InvalidCredential);
  }
  return p;
}

Result<TPM2B_PRIVATE> unmarshal_private(std::span<const std::uint8_t> b) {
  TPM2B_PRIVATE p{};
  std::size_t off = 0;
  if (Tss2_MU_TPM2B_PRIVATE_Unmarshal(b.data(), b.size(), &off, &p) != TSS2_RC_SUCCESS) {
    return std::unexpected(Status::InvalidCredential);
  }
  return p;
}

std::vector<std::uint8_t> encode_handle(std::span<const std::uint8_t> pub,
                                        std::span<const std::uint8_t> priv) {
  std::vector<std::uint8_t> h;
  h.reserve(4 + pub.size() + priv.size());
  h.push_back(static_cast<std::uint8_t>(pub.size() >> 8));
  h.push_back(static_cast<std::uint8_t>(pub.size()));
  h.insert(h.end(), pub.begin(), pub.end());
  h.push_back(static_cast<std::uint8_t>(priv.size() >> 8));
  h.push_back(static_cast<std::uint8_t>(priv.size()));
  h.insert(h.end(), priv.begin(), priv.end());
  return h;
}

Result<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> decode_handle(
    std::span<const std::uint8_t> h) {
  if (h.size() < 4) {
    return std::unexpected(Status::InvalidCredential);
  }
  const std::size_t pl = (static_cast<std::size_t>(h[0]) << 8) | h[1];
  if (h.size() < 2 + pl + 2) {
    return std::unexpected(Status::InvalidCredential);
  }
  const std::size_t vl = (static_cast<std::size_t>(h[2 + pl]) << 8) | h[3 + pl];
  if (h.size() != 4 + pl + vl) {
    return std::unexpected(Status::InvalidCredential);
  }
  return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{
      std::vector<std::uint8_t>(h.begin() + 2, h.begin() + 2 + static_cast<std::ptrdiff_t>(pl)),
      std::vector<std::uint8_t>(h.begin() + 4 + static_cast<std::ptrdiff_t>(pl), h.end())};
}

}  // namespace tpm2

namespace {

std::string rc_str(TSS2_RC rc) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%X", rc);
  return std::string(buf) + " " + Tss2_RC_Decode(rc);
}

class Tpm2KeyBackend;

class Tpm2SigningKey final : public SigningKey {
public:
  Tpm2SigningKey(Tpm2KeyBackend& owner, P256PublicKey pub, std::vector<std::uint8_t> handle)
      : owner_(owner), pub_(pub), handle_(std::move(handle)) {}
  BackendKind kind() const override { return BackendKind::Tpm2; }
  P256PublicKey pub() const override { return pub_; }
  Result<std::vector<std::uint8_t>> sign_der(std::span<const std::uint8_t> message) const override;
  std::vector<std::uint8_t> persist_handle() const override { return handle_; }

private:
  Tpm2KeyBackend& owner_;
  P256PublicKey pub_;
  std::vector<std::uint8_t> handle_;
};

class Tpm2KeyBackend final : public KeyBackend {
public:
  ~Tpm2KeyBackend() override { shutdown(); }

  BackendKind kind() const override { return BackendKind::Tpm2; }

  // Connects, creates the install-bound primary. `why` carries the reason.
  Result<void> init(const std::string& tcti, const Tpm2Params& params, std::string& why) {
    params_ = params;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(tcti.c_str(), &tcti_);
    if (rc != TSS2_RC_SUCCESS) {
      why = "tcti=" + tcti + " rc=" + rc_str(rc);
      return std::unexpected(Status::Other);
    }
    rc = Esys_Initialize(&esys_, tcti_, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
      why = "Esys_Initialize rc=" + rc_str(rc);
      shutdown();
      return std::unexpected(Status::Other);
    }
    // Harmless on an already-started TPM (TPM_RC_INITIALIZE).
    (void)Esys_Startup(esys_, TPM2_SU_CLEAR);

    auto in_pub = tpm2::primary_template(params_.srk_unique_seed);
    if (!in_pub) {
      why = "primary_template";
      shutdown();
      return std::unexpected(Status::Other);
    }
    TPM2B_SENSITIVE_CREATE in_sens{};
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION pcrs{};
    TPM2B_PUBLIC* out_pub = nullptr;
    TPM2B_CREATION_DATA* cdata = nullptr;
    TPM2B_DIGEST* chash = nullptr;
    TPMT_TK_CREATION* ctk = nullptr;
    const auto t0 = std::chrono::steady_clock::now();
    rc = Esys_CreatePrimary(esys_, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &in_sens, &*in_pub, &outside, &pcrs, &primary_, &out_pub, &cdata, &chash,
                            &ctk);
    Esys_Free(out_pub);
    Esys_Free(cdata);
    Esys_Free(chash);
    Esys_Free(ctk);
    if (rc != TSS2_RC_SUCCESS) {
      why = "Esys_CreatePrimary rc=" + rc_str(rc) +
            ((rc & 0xFFF) == TPM2_RC_BAD_AUTH ? " (owner auth set?)" : "");
      shutdown();
      return std::unexpected(Status::Other);
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    why = "tcti=" + tcti + " create_primary_ms=" + std::to_string(ms.count());
    tcti_name_ = tcti;
    return {};
  }

  Result<std::unique_ptr<SigningKey>> generate() override {
    std::lock_guard<std::mutex> lk(mu_);
    TPM2B_SENSITIVE_CREATE in_sens{};
    set_object_auth(in_sens);
    TPM2B_PUBLIC in_pub = tpm2::signing_child_template();
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION pcrs{};
    TPM2B_PRIVATE* out_priv = nullptr;
    TPM2B_PUBLIC* out_pub = nullptr;
    TPM2B_CREATION_DATA* cdata = nullptr;
    TPM2B_DIGEST* chash = nullptr;
    TPMT_TK_CREATION* ctk = nullptr;
    const TSS2_RC rc = Esys_Create(esys_, primary_, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &in_sens, &in_pub, &outside, &pcrs, &out_priv, &out_pub, &cdata,
                                   &chash, &ctk);
    OPENSSL_cleanse(&in_sens, sizeof(in_sens));
    Esys_Free(cdata);
    Esys_Free(chash);
    Esys_Free(ctk);
    if (rc != TSS2_RC_SUCCESS) {
      log::error("tpm_create_failed", {{"rc", rc_str(rc)}});
      Esys_Free(out_priv);
      Esys_Free(out_pub);
      return std::unexpected(Status::Other);
    }
    auto pub_b = tpm2::marshal_public(*out_pub);
    auto priv_b = tpm2::marshal_private(*out_priv);
    P256PublicKey pub{};
    const bool ok = out_pub->publicArea.unique.ecc.x.size == 32 &&
                    out_pub->publicArea.unique.ecc.y.size == 32;
    if (ok) {
      std::memcpy(pub.x.data(), out_pub->publicArea.unique.ecc.x.buffer, 32);
      std::memcpy(pub.y.data(), out_pub->publicArea.unique.ecc.y.buffer, 32);
    }
    Esys_Free(out_priv);
    Esys_Free(out_pub);
    if (!ok || !pub_b || !priv_b) {
      return std::unexpected(Status::Other);
    }
    log::debug("tpm_child_created", {{"pub_size", std::to_string(pub_b->size())},
                                     {"priv_size", std::to_string(priv_b->size())}});
    return std::make_unique<Tpm2SigningKey>(*this, pub, tpm2::encode_handle(*pub_b, *priv_b));
  }

  Result<std::unique_ptr<SigningKey>> load(std::span<const std::uint8_t> handle,
                                           const P256PublicKey& pub) override {
    // No TPM round trip here: decode the wrapped blob and check the public
    // point. Esys_Load happens per sign (DESIGN.md: Load + Sign + Flush).
    auto parts = tpm2::decode_handle(handle);
    if (!parts) {
      return std::unexpected(parts.error());
    }
    auto p = tpm2::unmarshal_public(parts->first);
    if (!p || p->publicArea.type != TPM2_ALG_ECC || p->publicArea.unique.ecc.x.size != 32 ||
        p->publicArea.unique.ecc.y.size != 32 ||
        std::memcmp(p->publicArea.unique.ecc.x.buffer, pub.x.data(), 32) != 0 ||
        std::memcmp(p->publicArea.unique.ecc.y.buffer, pub.y.data(), 32) != 0) {
      log::error("tpm_load_pub_mismatch");
      return std::unexpected(Status::InvalidCredential);
    }
    return std::make_unique<Tpm2SigningKey>(*this, pub,
                                            std::vector<std::uint8_t>(handle.begin(), handle.end()));
  }

  Result<void> destroy(std::span<const std::uint8_t>) override {
    return {};  // wrapped blobs live only in the store; nothing to free in the TPM
  }

  Result<std::vector<std::uint8_t>> wrap_secret(std::span<const std::uint8_t> secret) override {
    std::lock_guard<std::mutex> lk(mu_);
    if (secret.empty() || secret.size() > sizeof(TPM2B_SENSITIVE_DATA::buffer)) {
      return std::unexpected(Status::InvalidParameter);
    }
    TPM2B_SENSITIVE_CREATE in_sens{};
    set_object_auth(in_sens);
    in_sens.sensitive.data.size = static_cast<UINT16>(secret.size());
    std::memcpy(in_sens.sensitive.data.buffer, secret.data(), secret.size());
    TPM2B_PUBLIC in_pub = tpm2::seal_template();
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION pcrs{};
    TPM2B_PRIVATE* out_priv = nullptr;
    TPM2B_PUBLIC* out_pub = nullptr;
    TPM2B_CREATION_DATA* cdata = nullptr;
    TPM2B_DIGEST* chash = nullptr;
    TPMT_TK_CREATION* ctk = nullptr;
    const TSS2_RC rc = Esys_Create(esys_, primary_, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &in_sens, &in_pub, &outside, &pcrs, &out_priv, &out_pub, &cdata,
                                   &chash, &ctk);
    OPENSSL_cleanse(&in_sens, sizeof(in_sens));
    Esys_Free(cdata);
    Esys_Free(chash);
    Esys_Free(ctk);
    if (rc != TSS2_RC_SUCCESS) {
      log::error("tpm_seal_failed", {{"rc", rc_str(rc)}});
      Esys_Free(out_priv);
      Esys_Free(out_pub);
      return std::unexpected(Status::Other);
    }
    auto pub_b = tpm2::marshal_public(*out_pub);
    auto priv_b = tpm2::marshal_private(*out_priv);
    Esys_Free(out_priv);
    Esys_Free(out_pub);
    if (!pub_b || !priv_b) {
      return std::unexpected(Status::Other);
    }
    return tpm2::encode_handle(*pub_b, *priv_b);
  }

  Result<std::vector<std::uint8_t>> unwrap_secret(std::span<const std::uint8_t> wrapped) override {
    std::lock_guard<std::mutex> lk(mu_);
    auto h = load_transient(wrapped);
    if (!h) {
      return std::unexpected(h.error());
    }
    TPM2B_SENSITIVE_DATA* data = nullptr;
    const TSS2_RC rc = Esys_Unseal(esys_, h->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &data);
    Esys_FlushContext(esys_, h->handle);
    if (rc != TSS2_RC_SUCCESS) {
      log::error("tpm_unseal_failed", {{"rc", rc_str(rc)}});
      return std::unexpected(Status::Other);
    }
    std::vector<std::uint8_t> out(data->buffer, data->buffer + data->size);
    OPENSSL_cleanse(data, sizeof(*data));
    Esys_Free(data);
    return out;
  }

  Result<std::vector<std::uint8_t>> sign(std::span<const std::uint8_t> handle,
                                         std::span<const std::uint8_t> message) {
    std::lock_guard<std::mutex> lk(mu_);
    auto h = load_transient(handle);
    if (!h) {
      return std::unexpected(h.error());
    }
    Provider p;
    const auto digest = p.sha256(message);
    TPM2B_DIGEST d{};
    d.size = 32;
    std::memcpy(d.buffer, digest.data(), 32);
    TPMT_SIG_SCHEME scheme{};
    scheme.scheme = TPM2_ALG_ECDSA;
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    TPMT_TK_HASHCHECK validation{};
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_NULL;
    validation.digest.size = 0;
    TPMT_SIGNATURE* sig = nullptr;
    const auto t0 = std::chrono::steady_clock::now();
    const TSS2_RC rc = Esys_Sign(esys_, h->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &d,
                                 &scheme, &validation, &sig);
    Esys_FlushContext(esys_, h->handle);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    if (rc != TSS2_RC_SUCCESS) {
      log::error("tpm_sign_failed", {{"rc", rc_str(rc)}});
      return std::unexpected(Status::Other);
    }
    std::array<std::uint8_t, 32> r{}, s{};
    const auto& e = sig->signature.ecdsa;
    const bool ok = sig->sigAlg == TPM2_ALG_ECDSA && e.signatureR.size <= 32 &&
                    e.signatureS.size <= 32;
    if (ok) {
      std::memcpy(r.data() + (32 - e.signatureR.size), e.signatureR.buffer, e.signatureR.size);
      std::memcpy(s.data() + (32 - e.signatureS.size), e.signatureS.buffer, e.signatureS.size);
    }
    Esys_Free(sig);
    if (!ok) {
      return std::unexpected(Status::Other);
    }
    log::debug("tpm_sign", {{"tpm_sign_ms", std::to_string(ms.count())}});
    return Provider::ecdsa_p256_rs_to_der_low_s(r, s);
  }

private:
  struct Loaded {
    ESYS_TR handle{ESYS_TR_NONE};
    P256PublicKey pub{};
  };

  void set_object_auth(TPM2B_SENSITIVE_CREATE& in_sens) const {
    in_sens.sensitive.userAuth.size = 32;
    std::memcpy(in_sens.sensitive.userAuth.buffer, params_.object_auth.data(), 32);
  }

  Result<Loaded> load_transient(std::span<const std::uint8_t> handle) {
    auto parts = tpm2::decode_handle(handle);
    if (!parts) {
      return std::unexpected(parts.error());
    }
    auto pub = tpm2::unmarshal_public(parts->first);
    auto priv = tpm2::unmarshal_private(parts->second);
    if (!pub || !priv) {
      return std::unexpected(Status::InvalidCredential);
    }
    Loaded l;
    const TSS2_RC rc = Esys_Load(esys_, primary_, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &*priv, &*pub, &l.handle);
    if (rc != TSS2_RC_SUCCESS) {
      log::error("tpm_load_failed", {{"rc", rc_str(rc)}});
      return std::unexpected(Status::InvalidCredential);
    }
    TPM2B_AUTH auth{};
    auth.size = 32;
    std::memcpy(auth.buffer, params_.object_auth.data(), 32);
    const TSS2_RC arc = Esys_TR_SetAuth(esys_, l.handle, &auth);
    OPENSSL_cleanse(&auth, sizeof(auth));
    if (arc != TSS2_RC_SUCCESS) {
      Esys_FlushContext(esys_, l.handle);
      return std::unexpected(Status::Other);
    }
    if (pub->publicArea.type == TPM2_ALG_ECC && pub->publicArea.unique.ecc.x.size == 32 &&
        pub->publicArea.unique.ecc.y.size == 32) {
      std::memcpy(l.pub.x.data(), pub->publicArea.unique.ecc.x.buffer, 32);
      std::memcpy(l.pub.y.data(), pub->publicArea.unique.ecc.y.buffer, 32);
    }
    return l;
  }

  void shutdown() {
    if (esys_ != nullptr) {
      if (primary_ != ESYS_TR_NONE) {
        Esys_FlushContext(esys_, primary_);
        primary_ = ESYS_TR_NONE;
      }
      Esys_Finalize(&esys_);
      esys_ = nullptr;
    }
    if (tcti_ != nullptr) {
      Tss2_TctiLdr_Finalize(&tcti_);
      tcti_ = nullptr;
    }
    OPENSSL_cleanse(&params_, sizeof(params_));
  }

  std::mutex mu_;
  TSS2_TCTI_CONTEXT* tcti_{nullptr};
  ESYS_CONTEXT* esys_{nullptr};
  ESYS_TR primary_{ESYS_TR_NONE};
  Tpm2Params params_{};
  std::string tcti_name_;
};

Result<std::vector<std::uint8_t>> Tpm2SigningKey::sign_der(
    std::span<const std::uint8_t> message) const {
  return owner_.sign(handle_, message);
}

}  // namespace

std::unique_ptr<KeyBackend> make_tpm2_key_backend(const ProbeOptions& opt, std::string& why) {
  if (!opt.tpm_params) {
    why = "no tpm_params provider";
    return nullptr;
  }
  std::vector<std::string> tctis;
  if (!opt.tpm_tcti.empty()) {
    tctis.push_back(opt.tpm_tcti);
  } else {
    if (::access("/dev/tpmrm0", R_OK | W_OK) == 0) {
      tctis.push_back("device:/dev/tpmrm0");
    } else {
      why = "/dev/tpmrm0 not accessible";
    }
    if (opt.tpm_allow_notpmrm && ::access("/dev/tpm0", R_OK | W_OK) == 0) {
      tctis.push_back("device:/dev/tpm0");
    }
  }
  if (tctis.empty()) {
    if (why.empty()) {
      why = "no TCTI";
    }
    return nullptr;
  }
  auto params = opt.tpm_params();
  if (!params) {
    why = "tpm params unavailable";
    return nullptr;
  }
  for (const auto& t : tctis) {
    auto b = std::make_unique<Tpm2KeyBackend>();
    std::string reason;
    if (b->init(t, *params, reason)) {
      why = reason;
      OPENSSL_cleanse(&*params, sizeof(*params));
      return b;
    }
    why = reason;
    log::warn("tpm_probe_failed", {{"tcti", t}, {"err", reason}});
  }
  OPENSSL_cleanse(&*params, sizeof(*params));
  return nullptr;
}

}  // namespace swpk::crypto

#endif  // SWPASSKEY_TPM
