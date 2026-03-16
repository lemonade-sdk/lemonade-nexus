# BoringTun — Cloudflare's userspace WireGuard implementation (Rust → C FFI)
#
# Uses Corrosion (https://github.com/corrosion-rs/corrosion) to build our
# thin Rust wrapper crate (crates/boringtun-ffi/) that re-exports the
# BoringTun C FFI as a static library.
#
# Requirements: Rust toolchain (rustc + cargo) must be available.

include(FetchContent)

# --- Corrosion: CMake integration for Rust ---
FetchContent_Declare(corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG        v0.5.1
)
FetchContent_MakeAvailable(corrosion)

# --- Import our wrapper crate ---
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_SOURCE_DIR}/crates/boringtun-ffi/Cargo.toml"
    PROFILE       release
)

# Expose an INTERFACE target that downstream can link against.
# Link directly against Corrosion's imported target (lemonade_boringtun_ffi)
# which handles the correct library naming on all platforms (.a / .lib).
add_library(boringtun-ffi INTERFACE)
target_link_libraries(boringtun-ffi INTERFACE lemonade_boringtun_ffi)
target_include_directories(boringtun-ffi INTERFACE
    "${CMAKE_SOURCE_DIR}/crates/boringtun-ffi/include"
)

# Platform-specific system libraries needed by the Rust static lib
if(APPLE)
    target_link_libraries(boringtun-ffi INTERFACE
        "-framework Security"
        "-framework SystemConfiguration"
    )
elseif(UNIX)
    target_link_libraries(boringtun-ffi INTERFACE pthread dl m)
elseif(WIN32)
    target_link_libraries(boringtun-ffi INTERFACE ws2_32 userenv bcrypt ntdll)
endif()
