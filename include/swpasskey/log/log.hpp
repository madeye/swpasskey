#pragma once

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <utility>

namespace swpk::log {

enum class Level : std::uint8_t { Error = 0, Warn = 1, Info = 2, Debug = 3 };

void set_level(Level level);
void set_level_from_env();  // SWPASSKEY_LOG=error|warn|info|debug
Level level();

// One JSON object per line on stderr. Values are copied into the JSON as
// strings; callers must not pass secrets (PIN, keys, CBOR payloads).
void emit(Level level,
          std::string_view event,
          std::initializer_list<std::pair<std::string_view, std::string_view>> fields = {});

inline void error(std::string_view event,
                  std::initializer_list<std::pair<std::string_view, std::string_view>> fields = {}) {
  emit(Level::Error, event, fields);
}
inline void warn(std::string_view event,
                 std::initializer_list<std::pair<std::string_view, std::string_view>> fields = {}) {
  emit(Level::Warn, event, fields);
}
inline void info(std::string_view event,
                 std::initializer_list<std::pair<std::string_view, std::string_view>> fields = {}) {
  emit(Level::Info, event, fields);
}
inline void debug(std::string_view event,
                  std::initializer_list<std::pair<std::string_view, std::string_view>> fields = {}) {
  emit(Level::Debug, event, fields);
}

}  // namespace swpk::log
