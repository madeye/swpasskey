#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace swpk::ctl {

// Minimal JSON for the control socket: one flat object per line. Values are
// strings, integers, booleans, nested objects or arrays of objects.
class JsonWriter {
public:
  JsonWriter& begin_object();
  JsonWriter& end_object();
  JsonWriter& begin_array(std::string_view key);
  JsonWriter& end_array();
  JsonWriter& key(std::string_view k);
  JsonWriter& str(std::string_view key, std::string_view v);
  JsonWriter& num(std::string_view key, std::uint64_t v);
  JsonWriter& boolean(std::string_view key, bool v);
  JsonWriter& object(std::string_view key);  // begin nested object
  std::string finish();

private:
  void sep();
  void write_str(std::string_view v);
  std::string out_;
  std::vector<bool> first_;
};

// Parses a flat object of string / integer / boolean values. Nested values
// are rejected (the CLI never sends them).
struct JsonRequest {
  std::map<std::string, std::string> fields;
  bool ok{false};
  std::string error;
  std::string get(std::string_view k, std::string_view def = "") const;
};
JsonRequest parse_flat_json(std::string_view line);

}  // namespace swpk::ctl
