// authenticatorGetAssertion (0x02) + getNextAssertion (0x08).
#include "ctap_internal.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/log/log.hpp"

#include <algorithm>
#include <cstring>

namespace swpk::ctap {
namespace {

using cbor::Reader;
using cbor::Writer;
using detail::Entry;

struct GetAssertionRequest {
  std::string rp_id;
  bool have_rp_id{false};
  std::array<std::uint8_t, 32> client_data_hash{};
  bool have_client_data_hash{false};
  std::optional<std::vector<detail::PubKeyCredDescriptor>> allow_list;
  detail::ExtensionsIn ext;
  detail::Options options;
  std::optional<std::vector<std::uint8_t>> pin_uv_auth_param;
  std::optional<std::uint64_t> pin_uv_auth_protocol;
};

Result<GetAssertionRequest> parse(std::span<const std::uint8_t> body) {
  GetAssertionRequest q;
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
        auto v = r.tstr();
        if (!v) return std::unexpected(v.error());
        q.rp_id = *v;
        q.have_rp_id = true;
        break;
      }
      case 0x02: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        if (v->size() != 32) return std::unexpected(Status::InvalidParameter);
        std::memcpy(q.client_data_hash.data(), v->data(), 32);
        q.have_client_data_hash = true;
        break;
      }
      case 0x03: {
        auto v = detail::parse_descriptor_list(r);
        if (!v) return std::unexpected(v.error());
        q.allow_list = std::move(*v);
        break;
      }
      case 0x04: {
        auto v = detail::parse_extensions(r);
        if (!v) return std::unexpected(v.error());
        q.ext = *v;
        break;
      }
      case 0x05: {
        auto v = detail::parse_options(r);
        if (!v) return std::unexpected(v.error());
        q.options = *v;
        break;
      }
      case 0x06: {
        auto v = r.bstr();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_param = *v;
        break;
      }
      case 0x07: {
        auto v = r.uint();
        if (!v) return std::unexpected(v.error());
        q.pin_uv_auth_protocol = *v;
        break;
      }
      default:
        if (auto s = r.skip(); !s) return std::unexpected(s.error());
        break;
    }
  }
  if (!q.have_rp_id || !q.have_client_data_hash) {
    return std::unexpected(Status::MissingParameter);
  }
  return q;
}

}  // namespace

Result<std::vector<std::uint8_t>> Authenticator::build_assertion(
    const store::Credential& cred, std::span<const std::uint8_t, 32> rp_id_hash,
    std::span<const std::uint8_t, 32> client_data_hash, std::uint8_t flags, bool bump_counter,
    const detail::ExtensionsIn* ext, std::optional<std::size_t> number_of_credentials) {
  (void)ext;  // hmac-secret output lands in PR10
  auto key = load_key(cred);
  if (!key) {
    return std::unexpected(key.error());
  }
  const std::uint32_t count = bump_counter ? cred.sign_count + 1 : cred.sign_count;
  std::vector<std::uint8_t> ext_out;
  if (!ext_out.empty()) {
    flags |= detail::kFlagEd;
  }
  const auto auth_data = detail::build_auth_data(rp_id_hash, flags, count, {}, ext_out);
  std::vector<std::uint8_t> to_sign(auth_data);
  to_sign.insert(to_sign.end(), client_data_hash.begin(), client_data_hash.end());
  auto sig = (*key)->sign_der(to_sign);
  if (!sig) {
    log::error("sign_failed", {{"rp", cred.rp_id}});
    return std::unexpected(Status::Other);
  }
  // Persist the counter bump before the response is framed.
  if (bump_counter) {
    if (auto u = store_.update_count_and_used(cred.cred_id, count, now_unix()); !u) {
      return std::unexpected(Status::Other);
    }
  }
  detail::UserEntity user;
  user.id = cred.user_id;
  user.name = cred.user_name;
  user.display_name = cred.user_display;
  const bool uv = (flags & detail::kFlagUv) != 0;

  std::vector<Entry> resp;
  resp.emplace_back(Writer::encode_uint(1), detail::encode_descriptor(cred.cred_id));
  resp.emplace_back(Writer::encode_uint(2), Writer::encode_bstr(auth_data));
  resp.emplace_back(Writer::encode_uint(3), Writer::encode_bstr(*sig));
  resp.emplace_back(Writer::encode_uint(4), detail::encode_user(user, uv));
  if (number_of_credentials.has_value() && *number_of_credentials > 1) {
    resp.emplace_back(Writer::encode_uint(5), Writer::encode_uint(*number_of_credentials));
  }
  Writer w;
  w.write_map(std::move(resp));
  return w.finish();
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_assertion(
    std::span<const std::uint8_t> body, CancelToken& cancel) {
  auto fail = [this](Status s) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.get_assert_err;
    return std::unexpected(s);
  };
  next_state_.reset();

  auto q = parse(body);
  if (!q) {
    return fail(q.error());
  }
  if (q->rp_id.empty() || q->rp_id.size() > 255) {
    return fail(Status::InvalidParameter);
  }
  if (q->options.uv.has_value() && *q->options.uv) {
    return fail(Status::InvalidOption);
  }
  const bool up = !q->options.up.has_value() || *q->options.up;

  const auto rp_id_hash = crypto_.sha256(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(q->rp_id.data()),
                                    q->rp_id.size()));

  // Candidate credentials: all for this RP, filtered by allowList when present.
  std::vector<store::Credential> creds = store_.find_by_rp(rp_id_hash);
  if (q->allow_list.has_value() && !q->allow_list->empty()) {
    std::vector<store::Credential> filtered;
    for (const auto& d : *q->allow_list) {
      if (d.type != "public-key") {
        continue;
      }
      for (const auto& c : creds) {
        if (d.id.size() == c.cred_id.size() &&
            std::memcmp(d.id.data(), c.cred_id.data(), d.id.size()) == 0) {
          filtered.push_back(c);
        }
      }
    }
    creds = std::move(filtered);
  }

  // PIN / UV (PR9): optional on getAssertion (alwaysUv=false).
  PinAuthIn pin_in;
  pin_in.param = q->pin_uv_auth_param;
  pin_in.protocol = q->pin_uv_auth_protocol;
  auto uv = check_pin_auth(pin_in, q->client_data_hash, 0x02, q->rp_id, rp_id_hash, false, cancel);
  if (!uv) {
    return fail(uv.error());
  }

  if (creds.empty()) {
    return fail(Status::NoCredentials);
  }

  // Most recently used first; ties by creation time (newest first).
  std::stable_sort(creds.begin(), creds.end(), [](const auto& a, const auto& b) {
    if (a.last_used_unix != b.last_used_unix) {
      return a.last_used_unix > b.last_used_unix;
    }
    return a.created_unix > b.created_unix;
  });

  std::uint8_t flags = 0;
  if (*uv) {
    flags |= detail::kFlagUv;
  }
  if (up) {
    const auto decision = confirm_up(ui::PresenceRequest::Kind::GetAssertion, q->rp_id,
                                     creds.front().user_display.empty() ? creds.front().user_name
                                                                        : creds.front().user_display,
                                     rp_id_hash, cancel);
    if (decision == ui::Decision::Cancelled) {
      return fail(Status::KeepaliveCancel);
    }
    if (decision == ui::Decision::Deny) {
      return fail(Status::OperationDenied);
    }
    if (decision == ui::Decision::Timeout) {
      return fail(Status::UserActionTimeout);
    }
    flags |= detail::kFlagUp;
  }

  const std::size_t total = creds.size();
  const store::Credential first = creds.front();
  if (total > 1) {
    auto st = std::make_unique<detail::AssertionState>();
    st->remaining.assign(creds.begin() + 1, creds.end());
    st->rp_id_hash = rp_id_hash;
    st->client_data_hash = q->client_data_hash;
    st->flags = flags;
    st->bump_counter = up;
    st->ext = q->ext;
    st->expiry = std::chrono::steady_clock::now() + kUserActionTimeout;
    next_state_ = std::move(st);
  }

  auto r = build_assertion(first, rp_id_hash, q->client_data_hash, flags, /*bump=*/up, &q->ext,
                           total);
  if (!r) {
    next_state_.reset();
    return fail(r.error());
  }
  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.get_assert_ok;
  }
  log::info("get_assertion", {{"rp", q->rp_id},
                              {"up", up ? "1" : "0"},
                              {"creds", std::to_string(total)}});
  return r;
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_next_assertion() {
  if (!next_state_ || next_state_->remaining.empty() ||
      std::chrono::steady_clock::now() > next_state_->expiry) {
    next_state_.reset();
    return std::unexpected(Status::NotAllowed);
  }
  const store::Credential cred = next_state_->remaining.front();
  next_state_->remaining.erase(next_state_->remaining.begin());
  auto r = build_assertion(cred, next_state_->rp_id_hash, next_state_->client_data_hash,
                           next_state_->flags, next_state_->bump_counter, &next_state_->ext,
                           std::nullopt);
  if (next_state_->remaining.empty()) {
    next_state_.reset();
  }
  return r;
}

}  // namespace swpk::ctap
