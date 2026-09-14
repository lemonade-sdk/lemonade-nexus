# frost-ffi — FROST(Ed25519, SHA-512) threshold signatures (Rust → C FFI)
#
# Builds crates/frost-ffi/ (Zcash Foundation frost-ed25519, pinned) via
# Corrosion and exposes it as a static library. Corrosion itself is fetched
# by libraries/boringtun.cmake, which must be included first.

if(NOT COMMAND corrosion_import_crate)
    # Corrosion is normally made available by boringtun.cmake; guard so this
    # file can also be included standalone.
    include(FetchContent)
    FetchContent_Declare(corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG        b1fab721655c5c4b1b08a083d3cd29f163af75d0  # v0.5.1
    )
    FetchContent_MakeAvailable(corrosion)
endif()

corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_SOURCE_DIR}/crates/frost-ffi/Cargo.toml"
    PROFILE       release
)

# Link libcmt (not msvcrt) under /MT, matching the other Rust crates.
if(MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
    corrosion_add_target_rustflags(lemonade_frost_ffi "-Ctarget-feature=+crt-static")
endif()

add_library(frost-ffi INTERFACE)
target_link_libraries(frost-ffi INTERFACE lemonade_frost_ffi)
target_include_directories(frost-ffi INTERFACE
    "${CMAKE_SOURCE_DIR}/crates/frost-ffi/include"
)

# Platform-specific system libraries needed by the Rust static lib.
if(APPLE)
    target_link_libraries(frost-ffi INTERFACE
        "-framework Security"
        "-framework SystemConfiguration"
    )
elseif(UNIX)
    target_link_libraries(frost-ffi INTERFACE pthread dl m)
elseif(WIN32)
    target_link_libraries(frost-ffi INTERFACE ws2_32 userenv bcrypt ntdll)
endif()
