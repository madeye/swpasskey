add_library(swpasskey_warnings INTERFACE)
target_compile_options(swpasskey_warnings INTERFACE
  -Wall
  -Wextra
  -Werror
  -Wpedantic
  -Wconversion
  -Wshadow
  -Wno-psabi)

# Applied to swpasskey_ctap when that target exists (PR2+).
function(swpasskey_disable_exceptions target)
  target_compile_options(${target} PRIVATE -fno-exceptions -fno-rtti)
endfunction()
