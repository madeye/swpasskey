cmake_minimum_required(VERSION 3.28)
project(swpasskey VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

option(SWPASSKEY_ITEST "Build libfido2 integration tests" OFF)

include(cmake/CompilerFlags.cmake)

if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  execute_process(
    COMMAND brew --prefix openssl@3
    OUTPUT_VARIABLE OPENSSL_ROOT_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
endif()
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

add_library(swpasskey_log STATIC src/log/log.cpp)
target_include_directories(swpasskey_log PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(swpasskey_log PUBLIC swpasskey_warnings)
target_compile_features(swpasskey_log PUBLIC cxx_std_23)

add_library(swpasskey_cbor STATIC src/cbor/cbor.cpp)
target_include_directories(swpasskey_cbor PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(swpasskey_cbor PUBLIC swpasskey_warnings)
target_compile_features(swpasskey_cbor PUBLIC cxx_std_23)

add_library(swpasskey_hid_framer STATIC src/ctap/hid_framer.cpp)
target_include_directories(swpasskey_hid_framer PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(swpasskey_hid_framer PUBLIC swpasskey_warnings)
target_compile_features(swpasskey_hid_framer PUBLIC cxx_std_23)

add_library(swpasskey_crypto STATIC
  src/crypto/openssl_provider.cpp
  src/crypto/software_key_backend.cpp)
target_include_directories(swpasskey_crypto PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(swpasskey_crypto PUBLIC OpenSSL::Crypto swpasskey_warnings)
target_compile_features(swpasskey_crypto PUBLIC cxx_std_23)
set_source_files_properties(src/crypto/software_key_backend.cpp PROPERTIES
  COMPILE_FLAGS -Wno-deprecated-declarations)

add_executable(swpasskeyd src/daemon/main.cpp)
target_link_libraries(swpasskeyd PRIVATE swpasskey_log swpasskey_warnings)
target_compile_definitions(swpasskeyd PRIVATE
  SWPASSKEY_VERSION="${PROJECT_VERSION}")

enable_testing()
include(cmake/FetchCatch2.cmake)
add_executable(swpasskey_tests
  tests/smoke_test.cpp
  tests/hid_framer_test.cpp
  tests/cbor_test.cpp
  tests/crypto_test.cpp
  tests/key_backend_software_test.cpp)
target_link_libraries(swpasskey_tests PRIVATE
  Catch2::Catch2WithMain
  swpasskey_log
  swpasskey_cbor
  swpasskey_hid_framer
  swpasskey_crypto
  swpasskey_warnings)
include(Catch)
catch_discover_tests(swpasskey_tests)
