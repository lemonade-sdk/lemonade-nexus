# storage-threshold — threshold storage key over Ristretto255 (Rust → C FFI)
#
# Builds crates/storage-threshold/ (frost-ristretto255 and elastic-elgamal,
# pinned) via Corrosion and exposes it as a static library. Corrosion itself
# is fetched by libraries/boringtun.cmake, which must be included first.

if(NOT COMMAND corrosion_import_crate)
    include(FetchContent)
    FetchContent_Declare(corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG        b1fab721655c5c4b1b08a083d3cd29f163af75d0  # v0.5.1
    )
    FetchContent_MakeAvailable(corrosion)
endif()

corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_SOURCE_DIR}/crates/storage-threshold/Cargo.toml"
    PROFILE       release
)

# Link libcmt (not msvcrt) under /MT, matching the other Rust crates.
if(MSVC AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
    corrosion_add_target_rustflags(lemonade_storage_threshold "-Ctarget-feature=+crt-static")
endif()

add_library(storage-threshold INTERFACE)
target_link_libraries(storage-threshold INTERFACE lemonade_storage_threshold)
target_include_directories(storage-threshold INTERFACE
    "${CMAKE_SOURCE_DIR}/crates/storage-threshold/include"
)

# Platform-specific system libraries needed by the Rust static lib.
if(APPLE)
    target_link_libraries(storage-threshold INTERFACE
        "-framework Security"
        "-framework SystemConfiguration"
    )
elseif(UNIX)
    target_link_libraries(storage-threshold INTERFACE pthread dl m)
elseif(WIN32)
    target_link_libraries(storage-threshold INTERFACE ws2_32 userenv bcrypt ntdll)
endif()
