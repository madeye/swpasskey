#include "swpasskey/ctap/authenticator.hpp"

#include "ctap_internal.hpp"
#include "pin_state.hpp"
#include "swpasskey/log/log.hpp"

#include <chrono>
#include <string>

namespace swpk::ctap {
namespace {

const char* cmd_name(std::uint8_t cmd) {
  switch (cmd) {
    case kCmdMakeCredential:
      return "makeCredential";
    case kCmdGetAssertion:
      return "getAssertion";
    case kCmdGetInfo:
      return "getInfo";
    case kCmdClientPin:
      return "clientPIN";
    case kCmdReset:
      return "reset";
    case kCmdGetNextAssertion:
      return "getNextAssertion";
    default:
      return "unknown";
  }
}

const char* backend_name(crypto::BackendKind k) {
  switch (k) {
    case crypto::BackendKind::Software:
      return "software";
    case crypto::BackendKind::Tpm2:
      return "tpm2";
    case crypto::BackendKind::SecureEnclave:
      return "se";
  }
  return "software";
}

}  // namespace

Authenticator::Authenticator(AuthenticatorConfig cfg, crypto::Provider& crypto,
                             crypto::KeyBackend& primary_keys, crypto::KeyBackend& software_keys,
                             store::CredentialStore& store, ui::Presence& presence)
    : cfg_(cfg),
      crypto_(crypto),
      primary_(primary_keys),
      software_(software_keys),
      store_(store),
      presence_(presence),
      pin_(std::make_unique<detail::PinManager>(crypto, store, cfg.pin_failure_delay_base,
                                                cfg.pin_token_idle_timeout)) {}

Authenticator::~Authenticator() = default;

const char* Authenticator::primary_backend_name() const { return backend_name(primary_.kind()); }

AuthenticatorMetrics Authenticator::metrics() const {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  AuthenticatorMetrics m = metrics_;
  m.pin_fail = pin_->pin_fail_count();
  m.pin_block = pin_->pin_block_count();
  return m;
}

void Authenticator::count_status(std::uint8_t status) {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  ++metrics_.ctap_status[status];
}

std::uint64_t Authenticator::now_unix() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

GetInfoSnapshot Authenticator::get_info() const {
  GetInfoSnapshot s;
  s.versions = {"FIDO_2_1", "FIDO_2_0"};  // K24: PIN (PR9) + dual-credRandom hmac-secret (PR10)
  if (cfg_.u2f_enabled) {
    s.versions.emplace_back("U2F_V2");  // PR11; CTAP2 versions stay first
  }
  s.extensions = {"hmac-secret"};
  s.aaguid = cfg_.aaguid;
  s.options.client_pin = pin_->pin_set();
  s.options.pin_uv_auth_token = true;
  s.pin_protocols = {2};
  s.remaining_discoverable = static_cast<std::uint32_t>(store_.remaining());
  return s;
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_info() {
  return encode_get_info(get_info());
}

ui::Decision Authenticator::confirm_up(ui::PresenceRequest::Kind kind, const std::string& rp_id,
                                       const std::string& user_display,
                                       std::span<const std::uint8_t, 32> rp_id_hash,
                                       CancelToken& cancel) {
  if (cancel.is_cancelled()) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.up_cancel;
    return ui::Decision::Cancelled;
  }
  ui::PresenceRequest req;
  req.kind = kind;
  req.rp_id = rp_id;
  req.user_display = user_display;
  std::copy(rp_id_hash.begin(), rp_id_hash.end(), req.rp_id_hash.begin());
  cancel.set_up_needed(true);
  const ui::Decision d = presence_.confirm(req, cancel, cfg_.up_timeout);
  cancel.set_up_needed(false);
  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    switch (d) {
      case ui::Decision::Allow:
        ++metrics_.up_allow;
        break;
      case ui::Decision::Deny:
        ++metrics_.up_deny;
        break;
      case ui::Decision::Timeout:
        ++metrics_.up_timeout;
        break;
      case ui::Decision::Cancelled:
        ++metrics_.up_cancel;
        break;
    }
  }
  return d;
}

Result<bool> Authenticator::check_pin_auth(const PinAuthIn& in,
                                           std::span<const std::uint8_t, 32> client_data_hash,
                                           std::uint8_t permission, const std::string& rp_id,
                                           std::span<const std::uint8_t, 32> rp_id_hash,
                                           bool is_make, CancelToken& cancel) {
  if (!in.param.has_value()) {
    if (is_make && pin_->pin_set()) {
      return std::unexpected(Status::PuattRequired);  // makeCredUvNotRqd=false
    }
    return false;  // getAssertion without PIN is allowed (alwaysUv=false): UV=0
  }
  if (!in.protocol.has_value()) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*in.protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (in.param->empty()) {
    // CTAP 2.1 §6.1.2 step 1 / §6.2.2 step 1: zero-length param → collect UP,
    // then report whether a PIN is set. Used by platforms to pick a device.
    const auto d = confirm_up(is_make ? ui::PresenceRequest::Kind::MakeCredential
                                      : ui::PresenceRequest::Kind::GetAssertion,
                              rp_id, "", rp_id_hash, cancel);
    if (d == ui::Decision::Cancelled) {
      return std::unexpected(Status::KeepaliveCancel);
    }
    if (d != ui::Decision::Allow) {
      return std::unexpected(Status::OperationDenied);
    }
    return std::unexpected(pin_->pin_set() ? Status::PinInvalid : Status::PinNotSet);
  }
  return pin_->verify(*in.param, *in.protocol, client_data_hash, permission, rp_id);
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_client_pin(std::span<const std::uint8_t> body,
                                                                CancelToken& cancel) {
  return pin_->handle(body, cancel);
}

Result<std::unique_ptr<crypto::SigningKey>> Authenticator::load_key(const store::Credential& c) {
  if (c.backend == crypto::BackendKind::Software) {
    return software_.load(c.priv, c.pub);
  }
  if (primary_.kind() != c.backend) {
    log::error("key_backend_unavailable", {{"rp", c.rp_id},
                                           {"row_backend", backend_name(c.backend)},
                                           {"probed", backend_name(primary_.kind())}});
    return std::unexpected(Status::InvalidCredential);
  }
  auto k = primary_.load(c.handle, c.pub);
  if (!k) {
    log::error("key_load_failed", {{"rp", c.rp_id}, {"backend", backend_name(c.backend)}});
    return std::unexpected(Status::InvalidCredential);
  }
  return k;
}

void Authenticator::destroy_key(const store::Credential& c) {
  if (c.backend == crypto::BackendKind::Software) {
    (void)software_.destroy(c.priv);
  } else if (primary_.kind() == c.backend) {
    (void)primary_.destroy(c.handle);
  } else {
    log::warn("destroy_skipped_backend_unavailable", {{"backend", backend_name(c.backend)}});
  }
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_reset(CancelToken& cancel) {
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::Reset, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  next_state_.reset();
  auto r = store_.factory_reset([this](const store::Credential& c) { destroy_key(c); });
  if (!r) {
    return std::unexpected(Status::Other);
  }
  (void)pin_->regenerate_key_agreement();  // drops the token and the ECDH key
  log::warn("factory_reset");
  return std::vector<std::uint8_t>{};
}

Result<void> Authenticator::ctl_reset(CancelToken& cancel) {
  auto r = cmd_reset(cancel);
  if (!r) {
    return std::unexpected(r.error());
  }
  return {};
}

Result<std::vector<std::uint8_t>> Authenticator::handle_cbor(
    std::span<const std::uint8_t> request, CancelToken& cancel) {
  if (request.empty()) {
    return std::unexpected(Status::InvalidLength);
  }
  const std::uint8_t cmd = request[0];
  const auto body = request.subspan(1);
  const auto t0 = std::chrono::steady_clock::now();
  Result<std::vector<std::uint8_t>> r;
  switch (cmd) {
    case kCmdGetInfo:
      r = cmd_get_info();
      break;
    case kCmdMakeCredential:
      r = cmd_make_credential(body, cancel);
      break;
    case kCmdGetAssertion:
      r = cmd_get_assertion(body, cancel);
      break;
    case kCmdGetNextAssertion:
      r = cmd_get_next_assertion();
      break;
    case kCmdReset:
      r = cmd_reset(cancel);
      break;
    case kCmdClientPin:
      r = cmd_client_pin(body, cancel);
      break;
    default:
      r = std::unexpected(Status::InvalidCommand);
      break;
  }
  const std::uint8_t status = r ? 0 : static_cast<std::uint8_t>(r.error());
  count_status(status);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0);
  log::info("ctap", {{"cmd", cmd_name(cmd)},
                     {"status", std::to_string(status)},
                     {"ms", std::to_string(ms.count())}});
  return r;
}

}  // namespace swpk::ctap
