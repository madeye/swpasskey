#include "ctap_internal.hpp"

#include <cstring>

namespace swpk::ctap::detail {

using cbor::Reader;
using cbor::Writer;

Result<std::int64_t> read_int_key(Reader& r) {
  auto m = r.peek_major();
  if (!m) {
    return std::unexpected(Status::InvalidCbor);
  }
  if (*m != 0 && *m != 1) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  return r.integer();
}

Result<PubKeyCredDescriptor> parse_descriptor(Reader& r) {
  PubKeyCredDescriptor d;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) {
      return std::unexpected(k.error());
    }
    if (*k == "type") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      d.type = *v;
    } else if (*k == "id") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      d.id = *v;
    } else if (auto s = r.skip(); !s) {
      return std::unexpected(s.error());
    }
  }
  if (d.type.empty() || d.id.empty()) {
    return std::unexpected(Status::MissingParameter);
  }
  return d;
}

Result<std::vector<PubKeyCredDescriptor>> parse_descriptor_list(Reader& r) {
  std::vector<PubKeyCredDescriptor> out;
  auto n = r.array();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto d = parse_descriptor(r);
    if (!d) {
      return std::unexpected(d.error());
    }
    out.push_back(std::move(*d));
  }
  return out;
}

Result<RpEntity> parse_rp(Reader& r) {
  RpEntity rp;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  bool have_id = false;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) {
      return std::unexpected(k.error());
    }
    if (*k == "id") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      rp.id = *v;
      have_id = true;
    } else if (*k == "name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      rp.name = *v;
    } else if (auto s = r.skip(); !s) {
      return std::unexpected(s.error());
    }
  }
  if (!have_id) {
    return std::unexpected(Status::MissingParameter);
  }
  return rp;
}

Result<UserEntity> parse_user(Reader& r) {
  UserEntity u;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  bool have_id = false;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) {
      return std::unexpected(k.error());
    }
    if (*k == "id") {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      u.id = *v;
      have_id = true;
    } else if (*k == "name") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      u.name = *v;
    } else if (*k == "displayName") {
      auto v = r.tstr();
      if (!v) return std::unexpected(v.error());
      u.display_name = *v;
    } else if (auto s = r.skip(); !s) {
      return std::unexpected(s.error());
    }
  }
  if (!have_id) {
    return std::unexpected(Status::MissingParameter);
  }
  return u;
}

Result<Options> parse_options(Reader& r) {
  Options o;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) {
      return std::unexpected(k.error());
    }
    auto v = r.boolean();
    if (!v) {
      return std::unexpected(v.error());
    }
    if (*k == "rk") {
      o.rk = *v;
    } else if (*k == "up") {
      o.up = *v;
    } else if (*k == "uv") {
      o.uv = *v;
    }
    // Unknown options are ignored per spec.
  }
  return o;
}

Result<crypto::P256PublicKey> parse_cose_p256(Reader& r) {
  crypto::P256PublicKey pub;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  bool have_x = false, have_y = false;
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = read_int_key(r);
    if (!k) {
      return std::unexpected(k.error());
    }
    if (*k == -2 || *k == -3) {
      auto v = r.bstr();
      if (!v) return std::unexpected(v.error());
      if (v->size() != 32) return std::unexpected(Status::InvalidParameter);
      std::memcpy(*k == -2 ? pub.x.data() : pub.y.data(), v->data(), 32);
      (*k == -2 ? have_x : have_y) = true;
    } else if (*k == 1) {
      auto v = r.integer();
      if (!v) return std::unexpected(v.error());
      if (*v != 2) return std::unexpected(Status::InvalidParameter);  // kty EC2
    } else if (*k == -1) {
      auto v = r.integer();
      if (!v) return std::unexpected(v.error());
      if (*v != 1) return std::unexpected(Status::InvalidParameter);  // crv P-256
    } else if (auto s = r.skip(); !s) {
      return std::unexpected(s.error());
    }
  }
  if (!have_x || !have_y) {
    return std::unexpected(Status::MissingParameter);
  }
  return pub;
}

Result<ExtensionsIn> parse_extensions(Reader& r) {
  ExtensionsIn e;
  auto n = r.map();
  if (!n) {
    return std::unexpected(n.error());
  }
  for (std::size_t i = 0; i < *n; ++i) {
    auto k = r.tstr();
    if (!k) {
      return std::unexpected(k.error());
    }
    if (*k == "credProtect") {
      auto v = r.uint();
      if (!v) return std::unexpected(v.error());
      e.cred_protect = *v;
    } else if (*k == "hmac-secret" || *k == "hmac-create-secret") {
      auto m = r.peek_major();
      if (!m) return std::unexpected(m.error());
      if (*m == 7) {
        auto v = r.boolean();
        if (!v) return std::unexpected(v.error());
        e.hmac_create_secret = *v;
      } else if (*m == 5) {
        e.hmac_secret_present = true;
        auto hn = r.map();
        if (!hn) return std::unexpected(hn.error());
        for (std::size_t j = 0; j < *hn; ++j) {
          auto hk = read_int_key(r);
          if (!hk) return std::unexpected(hk.error());
          if (*hk == 1) {
            auto pub = parse_cose_p256(r);
            if (!pub) return std::unexpected(pub.error());
            e.hmac_key_agreement = *pub;
          } else if (*hk == 2) {
            auto v = r.bstr();
            if (!v) return std::unexpected(v.error());
            e.hmac_salt_enc = *v;
          } else if (*hk == 3) {
            auto v = r.bstr();
            if (!v) return std::unexpected(v.error());
            e.hmac_salt_auth = *v;
          } else if (*hk == 4) {
            auto v = r.uint();
            if (!v) return std::unexpected(v.error());
            e.hmac_pin_protocol = *v;
          } else if (auto s = r.skip(); !s) {
            return std::unexpected(s.error());
          }
        }
      } else if (auto s = r.skip(); !s) {
        return std::unexpected(s.error());
      }
    } else if (auto s = r.skip(); !s) {
      return std::unexpected(s.error());
    }
  }
  return e;
}

Result<bool> parse_pub_key_cred_params_has_es256(Reader& r) {
  auto n = r.array();
  if (!n) {
    return std::unexpected(n.error());
  }
  bool found = false;
  for (std::size_t i = 0; i < *n; ++i) {
    auto mn = r.map();
    if (!mn) return std::unexpected(mn.error());
    std::string type;
    std::optional<std::int64_t> alg;
    for (std::size_t j = 0; j < *mn; ++j) {
      auto k = r.tstr();
      if (!k) return std::unexpected(k.error());
      if (*k == "type") {
        auto v = r.tstr();
        if (!v) return std::unexpected(v.error());
        type = *v;
      } else if (*k == "alg") {
        auto v = r.integer();
        if (!v) return std::unexpected(v.error());
        alg = *v;
      } else if (auto s = r.skip(); !s) {
        return std::unexpected(s.error());
      }
    }
    if (type.empty() || !alg) {
      return std::unexpected(Status::MissingParameter);
    }
    if (type == "public-key" && *alg == -7) {
      found = true;
    }
  }
  return found;
}

std::vector<std::uint8_t> encode_cose_p256(const crypto::P256PublicKey& pub) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_int(1), Writer::encode_int(2));    // kty EC2
  m.emplace_back(Writer::encode_int(3), Writer::encode_int(-7));   // alg ES256
  m.emplace_back(Writer::encode_int(-1), Writer::encode_int(1));   // crv P-256
  m.emplace_back(Writer::encode_int(-2), Writer::encode_bstr(pub.x));
  m.emplace_back(Writer::encode_int(-3), Writer::encode_bstr(pub.y));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

std::vector<std::uint8_t> encode_descriptor(std::span<const std::uint8_t> cred_id) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_tstr("id"), Writer::encode_bstr(cred_id));
  m.emplace_back(Writer::encode_tstr("type"), Writer::encode_tstr("public-key"));
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

std::vector<std::uint8_t> encode_user(const UserEntity& u, bool full) {
  std::vector<Entry> m;
  m.emplace_back(Writer::encode_tstr("id"), Writer::encode_bstr(u.id));
  if (full) {
    if (!u.name.empty()) {
      m.emplace_back(Writer::encode_tstr("name"), Writer::encode_tstr(u.name));
    }
    if (!u.display_name.empty()) {
      m.emplace_back(Writer::encode_tstr("displayName"), Writer::encode_tstr(u.display_name));
    }
  }
  Writer w;
  w.write_map(std::move(m));
  return w.finish();
}

std::vector<std::uint8_t> build_auth_data(std::span<const std::uint8_t, 32> rp_id_hash,
                                          std::uint8_t flags, std::uint32_t sign_count,
                                          std::span<const std::uint8_t> attested_cred_data,
                                          std::span<const std::uint8_t> extensions_cbor) {
  std::vector<std::uint8_t> out;
  out.reserve(37 + attested_cred_data.size() + extensions_cbor.size());
  out.insert(out.end(), rp_id_hash.begin(), rp_id_hash.end());
  out.push_back(flags);
  out.push_back(static_cast<std::uint8_t>(sign_count >> 24));
  out.push_back(static_cast<std::uint8_t>(sign_count >> 16));
  out.push_back(static_cast<std::uint8_t>(sign_count >> 8));
  out.push_back(static_cast<std::uint8_t>(sign_count));
  out.insert(out.end(), attested_cred_data.begin(), attested_cred_data.end());
  out.insert(out.end(), extensions_cbor.begin(), extensions_cbor.end());
  return out;
}

std::vector<std::uint8_t> build_attested_credential_data(
    std::span<const std::uint8_t, 16> aaguid, std::span<const std::uint8_t> cred_id,
    const crypto::P256PublicKey& pub) {
  std::vector<std::uint8_t> out;
  out.insert(out.end(), aaguid.begin(), aaguid.end());
  out.push_back(static_cast<std::uint8_t>(cred_id.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(cred_id.size()));
  out.insert(out.end(), cred_id.begin(), cred_id.end());
  auto cose = encode_cose_p256(pub);
  out.insert(out.end(), cose.begin(), cose.end());
  return out;
}

}  // namespace swpk::ctap::detail
