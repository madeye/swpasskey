#include "swpasskey/cbor/cbor.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>

namespace swpk::cbor {
namespace {

void encode_type(std::vector<std::uint8_t>& buf, std::uint8_t major, std::uint64_t n) {
  const std::uint8_t mt = static_cast<std::uint8_t>(major << 5);
  if (n < 24) {
    buf.push_back(static_cast<std::uint8_t>(mt | n));
  } else if (n <= 0xFF) {
    buf.push_back(static_cast<std::uint8_t>(mt | 24));
    buf.push_back(static_cast<std::uint8_t>(n));
  } else if (n <= 0xFFFF) {
    buf.push_back(static_cast<std::uint8_t>(mt | 25));
    buf.push_back(static_cast<std::uint8_t>(n >> 8));
    buf.push_back(static_cast<std::uint8_t>(n));
  } else if (n <= 0xFFFFFFFFULL) {
    buf.push_back(static_cast<std::uint8_t>(mt | 26));
    buf.push_back(static_cast<std::uint8_t>(n >> 24));
    buf.push_back(static_cast<std::uint8_t>(n >> 16));
    buf.push_back(static_cast<std::uint8_t>(n >> 8));
    buf.push_back(static_cast<std::uint8_t>(n));
  } else {
    buf.push_back(static_cast<std::uint8_t>(mt | 27));
    for (int i = 7; i >= 0; --i) {
      buf.push_back(static_cast<std::uint8_t>(n >> (i * 8)));
    }
  }
}

}  // namespace

void Writer::append_type(std::uint8_t major, std::uint64_t n) {
  encode_type(buf_, major, n);
}

void Writer::write_uint(std::uint64_t v) { append_type(0, v); }

void Writer::write_int(std::int64_t v) {
  if (v >= 0) {
    write_uint(static_cast<std::uint64_t>(v));
    return;
  }
  append_type(1, static_cast<std::uint64_t>(-1 - v));
}

void Writer::write_bstr(std::span<const std::uint8_t> v) {
  append_type(2, v.size());
  buf_.insert(buf_.end(), v.begin(), v.end());
}

void Writer::write_tstr(std::string_view v) {
  append_type(3, v.size());
  buf_.insert(buf_.end(), v.begin(), v.end());
}

void Writer::write_bool(bool v) {
  buf_.push_back(v ? 0xF5 : 0xF4);
}

void Writer::write_array_header(std::size_t n) { append_type(4, n); }

void Writer::write_raw(std::span<const std::uint8_t> encoded) {
  buf_.insert(buf_.end(), encoded.begin(), encoded.end());
}

void Writer::write_map(
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> entries) {
  std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  append_type(5, entries.size());
  for (const auto& [k, v] : entries) {
    buf_.insert(buf_.end(), k.begin(), k.end());
    buf_.insert(buf_.end(), v.begin(), v.end());
  }
}

std::vector<std::uint8_t> Writer::finish() { return std::move(buf_); }

std::vector<std::uint8_t> Writer::encode_uint(std::uint64_t v) {
  Writer w;
  w.write_uint(v);
  return w.finish();
}
std::vector<std::uint8_t> Writer::encode_tstr(std::string_view v) {
  Writer w;
  w.write_tstr(v);
  return w.finish();
}
std::vector<std::uint8_t> Writer::encode_bstr(std::span<const std::uint8_t> v) {
  Writer w;
  w.write_bstr(v);
  return w.finish();
}
std::vector<std::uint8_t> Writer::encode_int(std::int64_t v) {
  Writer w;
  w.write_int(v);
  return w.finish();
}
std::vector<std::uint8_t> Writer::encode_bool(bool v) {
  Writer w;
  w.write_bool(v);
  return w.finish();
}

Reader::Reader(std::span<const std::uint8_t> in) : in_(in) {}

Result<std::pair<std::uint8_t, std::uint64_t>> Reader::take_head() {
  if (off_ >= in_.size()) {
    return std::unexpected(Status::InvalidCbor);
  }
  const std::uint8_t ib = in_[off_++];
  const std::uint8_t major = static_cast<std::uint8_t>(ib >> 5);
  const std::uint8_t ai = static_cast<std::uint8_t>(ib & 0x1F);
  if (ai == 31) {
    return std::unexpected(Status::InvalidCbor);  // indefinite
  }
  std::uint64_t n = ai;
  std::size_t extra = 0;
  if (ai == 24) {
    extra = 1;
  } else if (ai == 25) {
    extra = 2;
  } else if (ai == 26) {
    extra = 4;
  } else if (ai == 27) {
    extra = 8;
  } else if (ai > 27) {
    return std::unexpected(Status::InvalidCbor);
  }
  if (extra > 0) {
    if (off_ + extra > in_.size()) {
      return std::unexpected(Status::InvalidCbor);
    }
    n = 0;
    for (std::size_t i = 0; i < extra; ++i) {
      n = (n << 8) | in_[off_++];
    }
  }
  return std::pair<std::uint8_t, std::uint64_t>{major, n};
}

Result<std::span<const std::uint8_t>> Reader::take_bytes(std::uint64_t n) {
  if (n > in_.size() - off_) {
    return std::unexpected(Status::InvalidCbor);
  }
  const auto s = in_.subspan(off_, static_cast<std::size_t>(n));
  off_ += static_cast<std::size_t>(n);
  return s;
}

Result<std::uint64_t> Reader::uint() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first != 0) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  return h->second;
}

Result<std::int64_t> Reader::integer() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first == 0) {
    if (h->second > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return std::unexpected(Status::InvalidCbor);
    }
    return static_cast<std::int64_t>(h->second);
  }
  if (h->first == 1) {
    if (h->second > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return std::unexpected(Status::InvalidCbor);
    }
    return static_cast<std::int64_t>(-1) - static_cast<std::int64_t>(h->second);
  }
  return std::unexpected(Status::CborUnexpectedType);
}

Result<std::vector<std::uint8_t>> Reader::bstr() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first != 2) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  auto b = take_bytes(h->second);
  if (!b) {
    return std::unexpected(b.error());
  }
  return std::vector<std::uint8_t>(b->begin(), b->end());
}

Result<std::string> Reader::tstr() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first != 3) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  auto b = take_bytes(h->second);
  if (!b) {
    return std::unexpected(b.error());
  }
  return std::string(reinterpret_cast<const char*>(b->data()), b->size());
}

Result<bool> Reader::boolean() {
  if (off_ >= in_.size()) {
    return std::unexpected(Status::InvalidCbor);
  }
  const std::uint8_t ib = in_[off_++];
  if (ib == 0xF4) {
    return false;
  }
  if (ib == 0xF5) {
    return true;
  }
  return std::unexpected(Status::CborUnexpectedType);
}

Result<std::size_t> Reader::map() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first != 5) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  return static_cast<std::size_t>(h->second);
}

Result<std::uint8_t> Reader::peek_major() const {
  if (off_ >= in_.size()) {
    return std::unexpected(Status::InvalidCbor);
  }
  return static_cast<std::uint8_t>(in_[off_] >> 5);
}

constexpr unsigned kMaxSkipDepth = 32;

Result<void> Reader::skip_depth(unsigned depth) {
  if (depth > kMaxSkipDepth) {
    return std::unexpected(Status::InvalidCbor);
  }
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  switch (h->first) {
    case 0:
    case 1:
      return {};
    case 2:
    case 3: {
      auto b = take_bytes(h->second);
      if (!b) {
        return std::unexpected(b.error());
      }
      return {};
    }
    case 4: {
      for (std::uint64_t i = 0; i < h->second; ++i) {
        if (auto r = skip_depth(depth + 1); !r) {
          return r;
        }
      }
      return {};
    }
    case 5: {
      for (std::uint64_t i = 0; i < h->second; ++i) {
        if (auto r = skip_depth(depth + 1); !r) {
          return r;
        }
        if (auto r = skip_depth(depth + 1); !r) {
          return r;
        }
      }
      return {};
    }
    case 6:
      return skip_depth(depth + 1);  // tag: skip the tagged item
    case 7:
      // Simple values / floats: the head already consumed the argument bytes
      // for ai 24..27 (bool/null are ai 20/21/22 with no extra).
      return {};
    default:
      return std::unexpected(Status::InvalidCbor);
  }
}

Result<std::size_t> Reader::array() {
  auto h = take_head();
  if (!h) {
    return std::unexpected(h.error());
  }
  if (h->first != 4) {
    return std::unexpected(Status::CborUnexpectedType);
  }
  return static_cast<std::size_t>(h->second);
}

}  // namespace swpk::cbor
