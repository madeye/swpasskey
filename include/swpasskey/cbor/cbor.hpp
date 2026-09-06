#pragma once

#include "swpasskey/status.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace swpk::cbor {

class Writer {
public:
  void write_uint(std::uint64_t v);
  void write_int(std::int64_t v);
  void write_bstr(std::span<const std::uint8_t> v);
  void write_tstr(std::string_view v);
  void write_bool(bool v);
  void write_array_header(std::size_t n);
  // Append already-encoded CBOR bytes (e.g. a nested map built elsewhere).
  void write_raw(std::span<const std::uint8_t> encoded);
  void write_map(std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> entries);
  std::vector<std::uint8_t> finish();

  static std::vector<std::uint8_t> encode_uint(std::uint64_t v);
  static std::vector<std::uint8_t> encode_tstr(std::string_view v);
  static std::vector<std::uint8_t> encode_bstr(std::span<const std::uint8_t> v);
  static std::vector<std::uint8_t> encode_int(std::int64_t v);
  static std::vector<std::uint8_t> encode_bool(bool v);

private:
  std::vector<std::uint8_t> buf_;
  void append_type(std::uint8_t major, std::uint64_t n);
};

class Reader {
public:
  explicit Reader(std::span<const std::uint8_t> in);

  Result<std::uint64_t> uint();
  Result<std::int64_t> integer();
  Result<std::vector<std::uint8_t>> bstr();
  Result<std::string> tstr();
  Result<bool> boolean();
  Result<std::size_t> map();
  Result<std::size_t> array();
  // Skip one complete data item (any type, nested). For unknown map keys.
  Result<void> skip() { return skip_depth(0); }
  // Peek the major type of the next item (0..7) without consuming it.
  Result<std::uint8_t> peek_major() const;
  std::size_t offset() const { return off_; }
  bool done() const { return off_ >= in_.size(); }

private:
  std::span<const std::uint8_t> in_;
  std::size_t off_{0};
  Result<std::pair<std::uint8_t, std::uint64_t>> take_head();
  Result<void> skip_depth(unsigned depth);
  Result<std::span<const std::uint8_t>> take_bytes(std::uint64_t n);
};

}  // namespace swpk::cbor
