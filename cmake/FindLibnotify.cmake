# libnotify (Linux desktop notifications for user presence, PR8/K13).
# SWPASSKEY_LIBNOTIFY auto-ON when pkg-config finds it; the build never
# hard-fails without it — make_presence() falls back to StdinPresence.
find_package(PkgConfig)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBNOTIFY IMPORTED_TARGET libnotify)
endif()
if(NOT DEFINED SWPASSKEY_LIBNOTIFY)
  if(LIBNOTIFY_FOUND)
    set(SWPASSKEY_LIBNOTIFY ON)
  else()
    set(SWPASSKEY_LIBNOTIFY OFF)
  endif()
endif()
option(SWPASSKEY_LIBNOTIFY "Build the libnotify user-presence notification" ${SWPASSKEY_LIBNOTIFY})
if(SWPASSKEY_LIBNOTIFY AND NOT LIBNOTIFY_FOUND)
  message(FATAL_ERROR "SWPASSKEY_LIBNOTIFY=ON but libnotify was not found (pkg-config)")
endif()
message(STATUS "libnotify presence: ${SWPASSKEY_LIBNOTIFY}")
