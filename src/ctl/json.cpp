#include "swpasskey/ctl/json.hpp"

#include <cstdio>

namespace swpk::ctl {

void JsonWriter::sep() {
  if (!first_.empty()) {
    if (!first_.back()) {
      out_.push_back(',');
    }
    first_.back() = false;
  }
}

void JsonWriter::write_str(std::string_view v) {
  out_.push_back('"');
  for (char ch : v) {
    const auto c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"':
        out_ += "\\\"";
        break;
      case '\\':
        out_ += "\\\\";
        break;
      case '\n':
        out_ += "\\n";
        break;
      case '\r':
        out_ += "\\r";
        break;
      case '\t':
        out_ += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
          out_ += buf;
        } else {
          out_.push_back(ch);
        }
    }
  }
  out_.push_back('"');
}

JsonWriter& JsonWriter::begin_object() {
  sep();
  out_.push_back('{');
  first_.push_back(true);
  return *this;
}

JsonWriter& JsonWriter::end_object() {
  out_.push_back('}');
  first_.pop_back();
  return *this;
}

JsonWriter& JsonWriter::key(std::string_view k) {
  sep();
  write_str(k);
  out_.push_back(':');
  // The value that follows must not emit a separator.
  first_.push_back(true);
  first_.back() = true;
  // Pop immediately: the caller writes exactly one value via a primitive.
  first_.pop_back();
  return *this;
}

JsonWriter& JsonWriter::begin_array(std::string_view k) {
  key(k);
  out_.push_back('[');
  first_.push_back(true);
  return *this;
}

JsonWriter& JsonWriter::end_array() {
  out_.push_back(']');
  first_.pop_back();
  return *this;
}

JsonWriter& JsonWriter::object(std::string_view k) {
  key(k);
  out_.push_back('{');
  first_.push_back(true);
  return *this;
}

JsonWriter& JsonWriter::str(std::string_view k, std::string_view v) {
  key(k);
  write_str(v);
  return *this;
}

JsonWriter& JsonWriter::num(std::string_view k, std::uint64_t v) {
  key(k);
  out_ += std::to_string(v);
  return *this;
}

JsonWriter& JsonWriter::boolean(std::string_view k, bool v) {
  key(k);
  out_ += v ? "true" : "false";
  return *this;
}

std::string JsonWriter::finish() { return out_; }

std::string JsonRequest::get(std::string_view k, std::string_view def) const {
  auto it = fields.find(std::string(k));
  return it == fields.end() ? std::string(def) : it->second;
}

namespace {

void skip_ws(std::string_view s, std::size_t& i) {
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
    ++i;
  }
}

bool parse_string(std::string_view s, std::size_t& i, std::string& out) {
  if (i >= s.size() || s[i] != '"') {
    return false;
  }
  ++i;
  while (i < s.size()) {
    const char c = s[i++];
    if (c == '"') {
      return true;
    }
    if (c == '\\') {
      if (i >= s.size()) {
        return false;
      }
      const char e = s[i++];
      switch (e) {
        case '"':
          out.push_back('"');
          break;
        case '\\':
          out.push_back('\\');
          break;
        case '/':
          out.push_back('/');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          if (i + 4 > s.size()) {
            return false;
          }
          unsigned v = 0;
          for (int k = 0; k < 4; ++k) {
            const char h = s[i++];
            v <<= 4;
            if (h >= '0' && h <= '9') v |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') v |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') v |= static_cast<unsigned>(h - 'A' + 10);
            else return false;
          }
          if (v < 0x80) {
            out.push_back(static_cast<char>(v));
          } else if (v < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (v >> 6)));
            out.push_back(static_cast<char>(0x80 | (v & 0x3F)));
          } else {
            out.push_back(static_cast<char>(0xE0 | (v >> 12)));
            out.push_back(static_cast<char>(0x80 | ((v >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (v & 0x3F)));
          }
          break;
        }
        default:
          return false;
      }
    } else {
      out.push_back(c);
    }
  }
  return false;
}

}  // namespace

JsonRequest parse_flat_json(std::string_view s) {
  JsonRequest r;
  std::size_t i = 0;
  skip_ws(s, i);
  if (i >= s.size() || s[i] != '{') {
    r.error = "expected object";
    return r;
  }
  ++i;
  skip_ws(s, i);
  if (i < s.size() && s[i] == '}') {
    r.ok = true;
    return r;
  }
  for (;;) {
    skip_ws(s, i);
    std::string k;
    if (!parse_string(s, i, k)) {
      r.error = "bad key";
      return r;
    }
    skip_ws(s, i);
    if (i >= s.size() || s[i] != ':') {
      r.error = "expected ':'";
      return r;
    }
    ++i;
    skip_ws(s, i);
    std::string v;
    if (i < s.size() && s[i] == '"') {
      if (!parse_string(s, i, v)) {
        r.error = "bad string";
        return r;
      }
    } else if (i < s.size() && (s[i] == '{' || s[i] == '[')) {
      r.error = "nested values unsupported";
      return r;
    } else {
      const std::size_t start = i;
      while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ' ' && s[i] != '\n') {
        ++i;
      }
      v = std::string(s.substr(start, i - start));
      if (v.empty()) {
        r.error = "unsupported value";
        return r;
      }
    }
    r.fields[k] = v;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ',') {
      ++i;
      continue;
    }
    if (i < s.size() && s[i] == '}') {
      r.ok = true;
      return r;
    }
    r.error = "expected ',' or '}'";
    return r;
  }
}

}  // namespace swpk::ctl
