# virtual-netstack — in-process userspace TCP/IP termination (Rust → C FFI)
#
# Builds crates/virtual-netstack/ (smoltcp + mio) via Corrosion and exposes it
# as a static library. Corrosion itself is fetched by libraries/boringtun.cmake,
# which must be included first.

if(NOT COMMAND corrosion_import_crate)
    # Corrosion is normally made available by boringtun.cmake; guard so this
    # file can also be included standalone.
    include(FetchContent)
    FetchContent_Declare(corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG        v0.5.1
    )
    FetchContent_MakeAvailable(corrosion)
endif()

corrosion_import_crate(
    MANIFEST_PATH "${CMAKE_SOURCE_DIR}/crates/virtual-netstack/Cargo.toml"
    PROFILE       release
)

add_library(virtual-netstack INTERFACE)
target_link_libraries(virtual-netstack INTERFACE lemonade_virtual_netstack)
target_include_directories(virtual-netstack INTERFACE
    "${CMAKE_SOURCE_DIR}/crates/virtual-netstack/include"
)

# Platform-specific system libraries needed by the Rust static lib.
if(APPLE)
    target_link_libraries(virtual-netstack INTERFACE
        "-framework Security"
        "-framework SystemConfiguration"
    )
elseif(UNIX)
    target_link_libraries(virtual-netstack INTERFACE pthread dl m)
elseif(WIN32)
    target_link_libraries(virtual-netstack INTERFACE ws2_32 userenv bcrypt ntdll)
endif()
