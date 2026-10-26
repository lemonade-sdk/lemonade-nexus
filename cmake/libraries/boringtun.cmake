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
    GIT_TAG        b1fab721655c5c4b1b08a083d3cd29f163af75d0  # v0.5.1
)

# Probe Rust with the static CRT so Corrosion links libcmt (not msvcrt) under /MT
if(MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
    set(ENV{RUSTFLAGS} "-Ctarget-feature=+crt-static")
endif()

FetchContent_MakeAvailable(corrosion)

# Rust's standard library asks for the shared libgcc_s unwinder, which would
# keep libgcc_s.so.1 a runtime dependency of executables linked with
# -static-libgcc (LEMONADE_NEXUS_STATIC_DEPS on Linux). Executables take the
# unwinder from the static libgcc_eh instead, as rustc does for crt-static
# GNU targets. Shared libraries such as the SDK keep libgcc_s. Corrosion reads
# this variable in every later corrosion_import_crate call (virtual-netstack,
# frost, storage-threshold).
if(LEMONADE_NEXUS_STATIC_CXX_RUNTIME AND "gcc_s" IN_LIST Rust_CARGO_TARGET_LINK_NATIVE_LIBS)
    set(_rust_native_libs "")
    foreach(_lib IN LISTS Rust_CARGO_TARGET_LINK_NATIVE_LIBS)
        if(_lib STREQUAL "gcc_s")
            set(_lib "$<IF:$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>,gcc_eh,gcc_s>")
        endif()
        list(APPEND _rust_native_libs "${_lib}")
    endforeach()
    set(Rust_CARGO_TARGET_LINK_NATIVE_LIBS "${_rust_native_libs}")
    unset(_rust_native_libs)
    unset(_lib)
endif()

# --- Import our wrapper crate ---
corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_SOURCE_DIR}/crates/boringtun-ffi/Cargo.toml"
    PROFILE       release
)

# Same crt-static flag for the crate's own build.
if(MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
    corrosion_add_target_rustflags(lemonade_boringtun_ffi "-Ctarget-feature=+crt-static")
endif()

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
elseif(ANDROID)
    # Bionic has pthreads in libc; there is no libpthread.
    target_link_libraries(boringtun-ffi INTERFACE dl m)
elseif(UNIX)
    target_link_libraries(boringtun-ffi INTERFACE pthread dl m)
elseif(WIN32)
    target_link_libraries(boringtun-ffi INTERFACE ws2_32 userenv bcrypt ntdll)
endif()
