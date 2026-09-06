// CTAP1/U2F over CTAPHID_MSG (DESIGN.md "CTAP1/U2F (PR11)").
//
// U2F user keys go through `KeyBackend` exactly like CTAP2 credentials; the
// key handle *is* the 32-byte credId. Registrations are stored as ordinary
// resident rows with rp_id = "u2f:" + hex(application) and rp_id_hash =
// application, so `swpasskeyctl list` and reset see them like any other row.
#include "ctap_internal.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/log/log.hpp"

#include <openssl/crypto.h>

#include <cstring>
#include <optional>
#include <utility>

namespace swpk::ctap {
namespace {

// INS (FIDO U2F Raw Message Formats §3).
constexpr std::uint8_t kInsRegister = 0x01;
constexpr std::uint8_t kInsAuthenticate = 0x02;
constexpr std::uint8_t kInsVersion = 0x03;

// U2F_AUTHENTICATE control bytes (P1).
constexpr std::uint8_t kAuthEnforce = 0x03;      // enforce-user-presence-and-sign
constexpr std::uint8_t kAuthCheckOnly = 0x07;    // check-only (no UP, no signature)
constexpr std::uint8_t kAuthDontEnforce = 0x08;  // dont-enforce-user-presence-and-sign

// ISO 7816-4 status words.
constexpr std::uint16_t kSwOk = 0x9000;
constexpr std::uint16_t kSwConditionsNotSatisfied = 0x6985;
constexpr std::uint16_t kSwWrongData = 0x6A80;
constexpr std::uint16_t kSwIncorrectP1P2 = 0x6A86;
constexpr std::uint16_t kSwWrongLength = 0x6700;
constexpr std::uint16_t kSwInsNotSupported = 0x6D00;
constexpr std::uint16_t kSwClaNotSupported = 0x6E00;
constexpr std::uint16_t kSwExecutionError = 0x6F00;

constexpr char kAttestationCn[] = "swpasskey U2F Self-Attestation";

std::vector<std::uint8_t> sw(std::uint16_t status) {
  return {static_cast<std::uint8_t>(status >> 8), static_cast<std::uint8_t>(status & 0xFF)};
}

std::vector<std::uint8_t> respond(std::vector<std::uint8_t> data, std::uint16_t status) {
  data.push_back(static_cast<std::uint8_t>(status >> 8));
  data.push_back(static_cast<std::uint8_t>(status & 0xFF));
  return data;
}

void append(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> in) {
  out.insert(out.end(), in.begin(), in.end());
}

void append_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 24));
  out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(v.size() * 2);
  for (std::uint8_t b : v) {
    s.push_back(kDigits[b >> 4]);
    s.push_back(kDigits[b & 0x0F]);
  }
  return s;
}

// ANSI X9.62 uncompressed point, as U2F carries public keys on the wire.
std::array<std::uint8_t, 65> uncompressed(const crypto::P256PublicKey& pub) {
  std::array<std::uint8_t, 65> out{};
  out[0] = 0x04;
  std::memcpy(out.data() + 1, pub.x.data(), 32);
  std::memcpy(out.data() + 33, pub.y.data(), 32);
  return out;
}

struct Apdu {
  std::uint8_t cla{};
  std::uint8_t ins{};
  std::uint8_t p1{};
  std::uint8_t p2{};
  std::span<const std::uint8_t> data;
};

// CLA INS P1 P2 [Lc] [data] [Le]. Both the short form (1-byte Lc) and the
// extended form (0x00 hi lo) are accepted: libfido2 and python-fido2 always
// send the extended form with a 2-byte Le, older stacks send the short one.
std::optional<Apdu> parse_apdu(std::span<const std::uint8_t> in) {
  if (in.size() < 4) {
    return std::nullopt;
  }
  Apdu a;
  a.cla = in[0];
  a.ins = in[1];
  a.p1 = in[2];
  a.p2 = in[3];
  const auto rest = in.subspan(4);
  if (rest.size() <= 1) {
    return a;  // case 1 (no body) / case 2 short (Le only)
  }
  std::size_t lc = 0;
  std::size_t off = 0;
  std::size_t max_le = 1;
  if (rest[0] != 0) {
    lc = rest[0];
    off = 1;
  } else {
    if (rest.size() < 3) {
      return std::nullopt;
    }
    lc = (static_cast<std::size_t>(rest[1]) << 8) | rest[2];
    off = 3;
    max_le = 2;
  }
  if (rest.size() < off + lc || rest.size() - off - lc > max_le) {
    return std::nullopt;
  }
  a.data = rest.subspan(off, lc);
  return a;
}

// The U2F batch-attestation key: a software P-256 key plus its self-signed
// certificate, generated on the first U2F_REGISTER and kept in the encrypted
// store from then on.
struct AttestationMaterial {
  std::unique_ptr<crypto::SigningKey> key;
  std::vector<std::uint8_t> cert_der;
};

Result<AttestationMaterial> attestation_material(store::CredentialStore& store,
                                                 crypto::KeyBackend& software) {
  if (auto a = store.u2f_attestation(); a.has_value()) {
    if (a->priv.size() != 32 || a->cert_der.empty()) {
      return std::unexpected(Status::Other);
    }
    std::array<std::uint8_t, 32> scalar{};
    std::memcpy(scalar.data(), a->priv.data(), 32);
    auto pub = crypto::p256_pub_from_scalar(scalar);
    if (!pub) {
      OPENSSL_cleanse(scalar.data(), scalar.size());
      return std::unexpected(pub.error());
    }
    auto key = software.load(scalar, *pub);
    OPENSSL_cleanse(scalar.data(), scalar.size());
    if (!key) {
      return std::unexpected(key.error());
    }
    return AttestationMaterial{std::move(*key), std::move(a->cert_der)};
  }

  auto key = software.generate();
  if (!key) {
    return std::unexpected(key.error());
  }
  auto scalar = crypto::SoftwareKeyBackend::export_scalar_for_store(**key);
  if (!scalar) {
    return std::unexpected(scalar.error());
  }
  auto cert = crypto::make_self_signed_p256_cert(*scalar, (*key)->pub(), kAttestationCn);
  if (!cert) {
    OPENSSL_cleanse(scalar->data(), scalar->size());
    return std::unexpected(cert.error());
  }
  store::U2fAttestation a;
  a.priv.assign(scalar->begin(), scalar->end());
  a.cert_der = *cert;
  OPENSSL_cleanse(scalar->data(), scalar->size());
  if (auto s = store.set_u2f_attestation(std::move(a)); !s) {
    return std::unexpected(s.error());
  }
  log::info("u2f_attestation_created");
  return AttestationMaterial{std::move(*key), std::move(*cert)};
}

}  // namespace

std::vector<std::uint8_t> Authenticator::u2f_register(std::span<const std::uint8_t> data,
                                                      CancelToken& cancel) {
  if (data.size() != 64) {
    return sw(kSwWrongLength);
  }
  std::array<std::uint8_t, 32> challenge{};
  std::array<std::uint8_t, 32> application{};
  std::memcpy(challenge.data(), data.data(), 32);
  std::memcpy(application.data(), data.data() + 32, 32);
  const std::string rp_id = "u2f:" + hex(application);

  const auto decision =
      confirm_up(ui::PresenceRequest::Kind::MakeCredential, rp_id, "", application, cancel);
  if (decision != ui::Decision::Allow) {
    return sw(kSwConditionsNotSatisfied);  // Deny, Timeout and Cancelled alike
  }
  if (store_.remaining() == 0) {
    log::warn("u2f_register_store_full");
    return sw(kSwExecutionError);
  }

  auto attest = attestation_material(store_, software_);
  if (!attest) {
    log::error("u2f_attestation_failed");
    return sw(kSwExecutionError);
  }

  auto key = primary_.generate();
  if (!key) {
    log::error("key_generate_failed", {{"backend", primary_backend_name()}});
    return sw(kSwExecutionError);
  }

  store::Credential c;
  c.rp_id = rp_id;
  c.rp_id_hash = application;
  if (!crypto_.random(c.cred_id)) {  // the key handle
    return sw(kSwExecutionError);
  }
  c.backend = (*key)->kind();
  c.pub = (*key)->pub();
  c.sign_count = 1;
  c.created_unix = now_unix();
  c.last_used_unix = c.created_unix;
  if (c.backend == crypto::BackendKind::Software) {
    auto sc = crypto::SoftwareKeyBackend::export_scalar_for_store(**key);
    if (!sc) {
      return sw(kSwExecutionError);
    }
    c.priv.assign(sc->begin(), sc->end());
    OPENSSL_cleanse(sc->data(), sc->size());
  } else {
    c.handle = (*key)->persist_handle();
  }
  {
    std::array<std::uint8_t, 64> cred_random{};
    if (!crypto_.random(cred_random)) {
      return sw(kSwExecutionError);
    }
    auto wrapped = primary_.wrap_secret(cred_random);
    OPENSSL_cleanse(cred_random.data(), cred_random.size());
    if (!wrapped) {
      log::error("wrap_secret_failed", {{"backend", primary_backend_name()}});
      return sw(kSwExecutionError);
    }
    c.cred_random = std::move(*wrapped);
  }

  // sig = ES256(attestation key, 0x00 || application || challenge || keyHandle || userPub)
  const auto user_pub = uncompressed(c.pub);
  std::vector<std::uint8_t> to_sign;
  to_sign.reserve(1 + 32 + 32 + c.cred_id.size() + user_pub.size());
  to_sign.push_back(0x00);
  append(to_sign, application);
  append(to_sign, challenge);
  append(to_sign, c.cred_id);
  append(to_sign, user_pub);
  auto sig = attest->key->sign_der(to_sign);
  if (!sig) {
    log::error("u2f_attestation_sign_failed");
    return sw(kSwExecutionError);
  }

  // Persist before the response leaves the worker.
  if (auto p = store_.put(c); !p) {
    (void)primary_.destroy(c.handle);
    return sw(kSwExecutionError);
  }

  std::vector<std::uint8_t> out;
  out.reserve(1 + user_pub.size() + 1 + c.cred_id.size() + attest->cert_der.size() + sig->size());
  out.push_back(0x05);  // legacy reserved byte
  append(out, user_pub);
  out.push_back(static_cast<std::uint8_t>(c.cred_id.size()));
  append(out, c.cred_id);
  append(out, attest->cert_der);
  append(out, *sig);
  log::info("u2f_register", {{"rp", rp_id}, {"key_backend", primary_backend_name()}});
  return respond(std::move(out), kSwOk);
}

std::vector<std::uint8_t> Authenticator::u2f_authenticate(std::uint8_t p1,
                                                          std::span<const std::uint8_t> data,
                                                          CancelToken& cancel) {
  if (data.size() < 65) {
    return sw(kSwWrongLength);
  }
  const std::size_t kh_len = data[64];
  if (data.size() != 65 + kh_len) {
    return sw(kSwWrongLength);
  }
  if (p1 != kAuthEnforce && p1 != kAuthCheckOnly && p1 != kAuthDontEnforce) {
    return sw(kSwIncorrectP1P2);
  }
  std::array<std::uint8_t, 32> challenge{};
  std::array<std::uint8_t, 32> application{};
  std::memcpy(challenge.data(), data.data(), 32);
  std::memcpy(application.data(), data.data() + 32, 32);

  const auto cred = store_.find(application, data.subspan(65, kh_len));
  if (!cred.has_value()) {
    return sw(kSwWrongData);  // unknown key handle for this application
  }
  if (p1 == kAuthCheckOnly) {
    // "known handle" is reported as 0x6985; no UP, no signature.
    return sw(kSwConditionsNotSatisfied);
  }

  std::uint8_t presence = 0x00;
  bool bump = false;
  if (p1 == kAuthEnforce) {
    const auto decision = confirm_up(ui::PresenceRequest::Kind::GetAssertion, cred->rp_id, "",
                                     application, cancel);
    if (decision != ui::Decision::Allow) {
      return sw(kSwConditionsNotSatisfied);
    }
    presence = 0x01;
    bump = true;
  }
  const std::uint32_t count = bump ? cred->sign_count + 1 : cred->sign_count;

  auto key = load_key(*cred);
  if (!key) {
    return sw(kSwExecutionError);
  }
  // sig = ES256(user key, application || userPresence || counter || challenge)
  std::vector<std::uint8_t> to_sign;
  to_sign.reserve(32 + 1 + 4 + 32);
  append(to_sign, application);
  to_sign.push_back(presence);
  append_be32(to_sign, count);
  append(to_sign, challenge);
  auto sig = (*key)->sign_der(to_sign);
  if (!sig) {
    log::error("sign_failed", {{"rp", cred->rp_id}});
    return sw(kSwExecutionError);
  }
  // Persist the counter bump before the response is framed.
  if (bump) {
    if (auto u = store_.update_count_and_used(cred->cred_id, count, now_unix()); !u) {
      return sw(kSwExecutionError);
    }
  }

  std::vector<std::uint8_t> out;
  out.reserve(1 + 4 + sig->size());
  out.push_back(presence);
  append_be32(out, count);
  append(out, *sig);
  log::info("u2f_authenticate", {{"rp", cred->rp_id},
                                 {"up", presence != 0 ? "1" : "0"},
                                 {"count", std::to_string(count)}});
  return respond(std::move(out), kSwOk);
}

std::vector<std::uint8_t> Authenticator::handle_u2f(std::span<const std::uint8_t> apdu,
                                                    CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  if (!cfg_.u2f_enabled) {
    return sw(kSwInsNotSupported);
  }
  const auto req = parse_apdu(apdu);
  if (!req.has_value()) {
    return sw(kSwWrongLength);
  }
  if (req->cla != 0x00) {
    return sw(kSwClaNotSupported);
  }
  switch (req->ins) {
    case kInsVersion: {
      static constexpr char kVersion[] = "U2F_V2";
      std::vector<std::uint8_t> out(std::begin(kVersion), std::end(kVersion) - 1);
      return respond(std::move(out), kSwOk);
    }
    case kInsRegister:
      return u2f_register(req->data, cancel);
    case kInsAuthenticate:
      return u2f_authenticate(req->p1, req->data, cancel);
    default:
      return sw(kSwInsNotSupported);
  }
}

}  // namespace swpk::ctap
