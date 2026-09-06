#include "swpasskey/log/log.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string>

namespace swpk::log {
namespace {

Level g_level = Level::Info;
std::mutex g_mu;

const char* level_name(Level level) {
  switch (level) {
    case Level::Error:
      return "error";
    case Level::Warn:
      return "warn";
    case Level::Info:
      return "info";
    case Level::Debug:
      return "debug";
  }
  return "info";
}

void append_escaped(std::string& out, std::string_view in) {
  out.push_back('"');
  for (char ch : in) {
    const auto c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20U) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x",
                        static_cast<unsigned>(c));
          out += buf;
        } else {
          out.push_back(ch);
        }
        break;
    }
  }
  out.push_back('"');
}

std::string iso8601_utc() {
  using clock = std::chrono::system_clock;
  const auto now = clock::now();
  const auto secs = clock::to_time_t(now);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch())
                      .count() %
                  1000;
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &secs);
#else
  gmtime_r(&secs, &tm);
#endif
  char buf[40];
  const int n = std::snprintf(buf, sizeof(buf),
                              "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                              tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                              tm.tm_hour, tm.tm_min, tm.tm_sec,
                              static_cast<int>(ms));
  if (n <= 0) {
    return "1970-01-01T00:00:00.000Z";
  }
  return std::string(buf, static_cast<std::size_t>(n));
}

}  // namespace

void set_level(Level level) {
  std::lock_guard<std::mutex> lock(g_mu);
  g_level = level;
}

void set_level_from_env() {
  const char* env = std::getenv("SWPASSKEY_LOG");
  if (env == nullptr) {
    return;
  }
  const std::string_view v{env};
  if (v == "error") {
    set_level(Level::Error);
  } else if (v == "warn") {
    set_level(Level::Warn);
  } else if (v == "info") {
    set_level(Level::Info);
  } else if (v == "debug") {
    set_level(Level::Debug);
  }
}

Level level() {
  std::lock_guard<std::mutex> lock(g_mu);
  return g_level;
}

void emit(Level lvl,
          std::string_view event,
          std::initializer_list<std::pair<std::string_view, std::string_view>> fields) {
  Level current = Level::Info;
  {
    std::lock_guard<std::mutex> lock(g_mu);
    current = g_level;
  }
  if (static_cast<std::uint8_t>(lvl) > static_cast<std::uint8_t>(current)) {
    return;
  }

  std::string line;
  line.reserve(128);
  line += "{\"ts\":";
  append_escaped(line, iso8601_utc());
  line += ",\"lvl\":";
  append_escaped(line, level_name(lvl));
  line += ",\"event\":";
  append_escaped(line, event);
  for (const auto& [k, v] : fields) {
    line += ',';
    append_escaped(line, k);
    line += ':';
    append_escaped(line, v);
  }
  line += "}\n";

  std::lock_guard<std::mutex> lock(g_mu);
  std::fwrite(line.data(), 1, line.size(), stderr);
  std::fflush(stderr);
}

}  // namespace swpk::log
