cmake_minimum_required(VERSION 3.28)
project(swpasskey VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

option(SWPASSKEY_ITEST "Build libfido2 integration tests" OFF)

include(cmake/CompilerFlags.cmake)

add_library(swpasskey_log STATIC src/log/log.cpp)
target_include_directories(swpasskey_log PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(swpasskey_log PUBLIC swpasskey_warnings)
target_compile_features(swpasskey_log PUBLIC cxx_std_23)

add_executable(swpasskeyd src/daemon/main.cpp)
target_link_libraries(swpasskeyd PRIVATE swpasskey_log swpasskey_warnings)
target_compile_definitions(swpasskeyd PRIVATE
  SWPASSKEY_VERSION="${PROJECT_VERSION}")

enable_testing()
include(cmake/FetchCatch2.cmake)
add_executable(swpasskey_tests tests/smoke_test.cpp)
target_link_libraries(swpasskey_tests PRIVATE
  Catch2::Catch2WithMain
  swpasskey_log
  swpasskey_warnings)
include(Catch)
catch_discover_tests(swpasskey_tests)
