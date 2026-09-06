#include "swpasskey/ctap/authenticator.hpp"

#include "swpasskey/log/log.hpp"

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

}  // namespace

Authenticator::Authenticator(AuthenticatorConfig cfg, crypto::Provider& crypto,
                             crypto::KeyBackend& primary_keys, crypto::KeyBackend& software_keys,
                             store::CredentialStore& store, ui::Presence& presence)
    : cfg_(cfg),
      crypto_(crypto),
      primary_(primary_keys),
      software_(software_keys),
      store_(store),
      presence_(presence) {}

const char* Authenticator::primary_backend_name() const {
  switch (primary_.kind()) {
    case crypto::BackendKind::Software:
      return "software";
    case crypto::BackendKind::Tpm2:
      return "tpm2";
    case crypto::BackendKind::SecureEnclave:
      return "se";
  }
  return "software";
}

AuthenticatorMetrics Authenticator::metrics() const {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  return metrics_;
}

GetInfoSnapshot Authenticator::get_info() const {
  GetInfoSnapshot s;
  s.aaguid = cfg_.aaguid;
  s.remaining_discoverable = static_cast<std::uint32_t>(store_.remaining());
  return s;
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_info() {
  return encode_get_info(get_info());
}

Result<std::vector<std::uint8_t>> Authenticator::handle_cbor(
    std::span<const std::uint8_t> request, CancelToken& cancel) {
  (void)cancel;
  if (request.empty()) {
    return std::unexpected(Status::InvalidLength);
  }
  const std::uint8_t cmd = request[0];
  const auto body = request.subspan(1);
  (void)body;
  Result<std::vector<std::uint8_t>> r;
  switch (cmd) {
    case kCmdGetInfo:
      r = cmd_get_info();
      break;
    default:
      r = std::unexpected(Status::InvalidCommand);
      break;
  }
  const std::uint8_t status = r ? 0 : static_cast<std::uint8_t>(r.error());
  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.ctap_status[status];
  }
  log::info("ctap", {{"cmd", cmd_name(cmd)}, {"status", std::to_string(status)}});
  return r;
}

std::vector<std::uint8_t> Authenticator::handle_u2f(std::span<const std::uint8_t> request,
                                                    CancelToken& cancel) {
  (void)request;
  (void)cancel;
  // SW = 0x6D00 INS not supported until PR11.
  return {0x6D, 0x00};
}

}  // namespace swpk::ctap
