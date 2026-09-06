cmake_minimum_required(VERSION 3.28)
project(swpasskey VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

option(SWPASSKEY_ITEST "Build libfido2 integration tests" OFF)
option(SWPASSKEY_ENABLE_U2F "Enable CTAP1/U2F over CTAPHID_MSG" ON)

include(cmake/CompilerFlags.cmake)

if(APPLE)
  enable_language(OBJCXX)
  set(CMAKE_OBJCXX_STANDARD 23)
  set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
endif()

if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  execute_process(
    COMMAND brew --prefix openssl@3
    OUTPUT_VARIABLE OPENSSL_ROOT_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
endif()
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

set(SWPK_INCLUDE ${CMAKE_SOURCE_DIR}/include)

function(swpk_lib name)
  add_library(${name} STATIC ${ARGN})
  target_include_directories(${name} PUBLIC ${SWPK_INCLUDE})
  target_link_libraries(${name} PUBLIC swpasskey_warnings)
  target_compile_features(${name} PUBLIC cxx_std_23)
endfunction()

# --- log --------------------------------------------------------------------
swpk_lib(swpasskey_log src/log/log.cpp)

# --- cbor -------------------------------------------------------------------
swpk_lib(swpasskey_cbor src/cbor/cbor.cpp)

# --- crypto -----------------------------------------------------------------
include(cmake/FindTss2.cmake)
set(SWPK_CRYPTO_SOURCES
  src/crypto/openssl_provider.cpp
  src/crypto/software_key_backend.cpp
  src/crypto/self_signed_cert.cpp
  src/crypto/probe.cpp)
if(APPLE)
  list(APPEND SWPK_CRYPTO_SOURCES src/crypto/se_key_backend.mm)
endif()
if(SWPASSKEY_TPM)
  list(APPEND SWPK_CRYPTO_SOURCES src/crypto/tpm2_key_backend.cpp)
endif()
swpk_lib(swpasskey_crypto ${SWPK_CRYPTO_SOURCES})
target_link_libraries(swpasskey_crypto PUBLIC OpenSSL::Crypto swpasskey_log)
if(SWPASSKEY_TPM)
  target_compile_definitions(swpasskey_crypto PUBLIC SWPASSKEY_TPM=1)
  target_link_libraries(swpasskey_crypto PUBLIC
    PkgConfig::TSS2_ESYS PkgConfig::TSS2_TCTILDR PkgConfig::TSS2_MU PkgConfig::TSS2_RC)
  # tpm2-tss .pc files list -l before -L, which FindPkgConfig cannot resolve
  # for a non-system prefix; add the directories explicitly.
  target_link_directories(swpasskey_crypto PUBLIC
    ${TSS2_ESYS_LIBRARY_DIRS} ${TSS2_TCTILDR_LIBRARY_DIRS} ${TSS2_MU_LIBRARY_DIRS} ${TSS2_RC_LIBRARY_DIRS})
endif()
set_source_files_properties(src/crypto/software_key_backend.cpp src/crypto/self_signed_cert.cpp
  PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
if(APPLE)
  set_source_files_properties(src/crypto/se_key_backend.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc")
  target_link_libraries(swpasskey_crypto PUBLIC "-framework Security" "-framework Foundation")
endif()

# --- store ------------------------------------------------------------------
set(SWPK_STORE_SOURCES
  src/store/credential_store.cpp
  src/store/file_store.cpp
  src/store/keychain.cpp)
if(APPLE)
  list(APPEND SWPK_STORE_SOURCES src/store/keychain_macos.mm)
else()
  list(APPEND SWPK_STORE_SOURCES src/store/keychain_linux.cpp)
endif()
swpk_lib(swpasskey_store ${SWPK_STORE_SOURCES})
target_link_libraries(swpasskey_store PUBLIC swpasskey_crypto swpasskey_cbor swpasskey_log)
if(APPLE)
  set_source_files_properties(src/store/keychain_macos.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc")
  target_link_libraries(swpasskey_store PUBLIC "-framework Security" "-framework Foundation")
else()
  find_package(PkgConfig)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBSECRET IMPORTED_TARGET libsecret-1)
  endif()
  option(SWPASSKEY_LIBSECRET "Store the DEK in libsecret" ${LIBSECRET_FOUND})
  if(SWPASSKEY_LIBSECRET)
    if(NOT LIBSECRET_FOUND)
      message(FATAL_ERROR "SWPASSKEY_LIBSECRET=ON but libsecret-1 was not found (pkg-config)")
    endif()
    target_compile_definitions(swpasskey_store PRIVATE SWPASSKEY_LIBSECRET=1)
    target_link_libraries(swpasskey_store PUBLIC PkgConfig::LIBSECRET)
  endif()
  message(STATUS "libsecret DEK storage: ${SWPASSKEY_LIBSECRET}")
endif()

# --- ui ---------------------------------------------------------------------
swpk_lib(swpasskey_ui src/ui/presence.cpp)
target_link_libraries(swpasskey_ui PUBLIC swpasskey_log)
# AutoAllowPresence exists only in Debug builds (never in release presets).
target_compile_definitions(swpasskey_ui PUBLIC
  $<$<CONFIG:Debug>:SWPASSKEY_ALLOW_TESTING_PRESENCE>)

# --- ctap (no exceptions / no RTTI) -------------------------------------------
swpk_lib(swpasskey_ctap
  src/ctap/hid_framer.cpp
  src/ctap/hid_device.cpp
  src/ctap/get_info.cpp
  src/ctap/auth_data.cpp
  src/ctap/authenticator.cpp
  src/ctap/make_credential.cpp
  src/ctap/get_assertion.cpp
  src/ctap/client_pin.cpp
  src/ctap/hmac_secret.cpp
  src/ctap/u2f.cpp)
target_link_libraries(swpasskey_ctap PUBLIC
  swpasskey_crypto swpasskey_store swpasskey_cbor swpasskey_ui swpasskey_log)
swpasskey_disable_exceptions(swpasskey_ctap)
if(SWPASSKEY_ENABLE_U2F)
  # PUBLIC so the daemon (via swpasskey_daemon) sees it and can default
  # AuthenticatorConfig::u2f_enabled to true.
  target_compile_definitions(swpasskey_ctap PUBLIC SWPASSKEY_ENABLE_U2F=1)
endif()

# --- hid transports -----------------------------------------------------------
if(APPLE)
  swpk_lib(swpasskey_hid src/hid/iokit_transport.mm src/hid/socket_transport.cpp)
  set_source_files_properties(src/hid/iokit_transport.mm PROPERTIES
    COMPILE_FLAGS "-fobjc-arc")
  target_link_libraries(swpasskey_hid PUBLIC
    "-framework IOKit" "-framework CoreFoundation" "-framework Foundation")
else()
  swpk_lib(swpasskey_hid src/hid/uhid_transport.cpp src/hid/socket_transport.cpp)
endif()
target_link_libraries(swpasskey_hid PUBLIC swpasskey_log)

# --- daemon core (loop, paths) ------------------------------------------------
swpk_lib(swpasskey_daemon
  src/daemon/loop.cpp
  src/daemon/paths.cpp)
target_link_libraries(swpasskey_daemon PUBLIC
  swpasskey_ctap swpasskey_hid swpasskey_log Threads::Threads)

# --- control socket (server + client helper) -----------------------------------
swpk_lib(swpasskey_ctl src/ctl/server.cpp src/ctl/json.cpp)
target_link_libraries(swpasskey_ctl PUBLIC swpasskey_daemon swpasskey_log)

# --- executables ------------------------------------------------------------
add_executable(swpasskeyd src/daemon/main.cpp)
target_link_libraries(swpasskeyd PRIVATE swpasskey_daemon swpasskey_ctl swpasskey_warnings)
add_executable(swpasskeyctl src/ctl/main.cpp)
target_link_libraries(swpasskeyctl PRIVATE swpasskey_ctl swpasskey_warnings)
target_compile_definitions(swpasskeyd PRIVATE
  SWPASSKEY_VERSION="${PROJECT_VERSION}")

# --- tests ------------------------------------------------------------------
enable_testing()
include(cmake/FetchCatch2.cmake)
add_executable(swpasskey_tests
  tests/smoke_test.cpp
  tests/hid_framer_test.cpp
  tests/cbor_test.cpp
  tests/crypto_test.cpp
  tests/key_backend_software_test.cpp
  tests/get_info_test.cpp
  tests/get_info_golden_test.cpp
  tests/hid_device_test.cpp
  tests/keepalive_loop_test.cpp
  tests/paths_test.cpp
  tests/make_credential_test.cpp
  tests/get_assertion_test.cpp
  tests/packed_self_attest_golden_test.cpp
  tests/u2f_test.cpp
  tests/store_test.cpp
  tests/pin_test.cpp
  tests/hmac_secret_test.cpp
  tests/ctl_test.cpp
  $<$<BOOL:${SWPASSKEY_TPM}>:tests/tpm_primary_template_test.cpp>
  $<$<BOOL:${SWPASSKEY_TPM}>:tests/itest/tpm_swtpm_itest.cpp>)
if(SWPASSKEY_TPM)
  target_include_directories(swpasskey_tests PRIVATE ${CMAKE_SOURCE_DIR}/src/crypto)
endif()
target_link_libraries(swpasskey_tests PRIVATE
  Catch2::Catch2WithMain
  swpasskey_daemon
  swpasskey_ctl
  swpasskey_warnings)
include(Catch)
catch_discover_tests(swpasskey_tests)

if(SWPASSKEY_ITEST)
  add_executable(swpasskey_itest tests/itest/libfido2_itest.cpp)
  target_link_libraries(swpasskey_itest PRIVATE Catch2::Catch2WithMain swpasskey_log swpasskey_warnings)
  target_compile_definitions(swpasskey_itest PRIVATE
    SWPASSKEY_BIN_DIR="${CMAKE_BINARY_DIR}")
  add_test(NAME swpasskey_itest COMMAND swpasskey_itest)
endif()
