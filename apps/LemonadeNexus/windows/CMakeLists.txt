cmake_minimum_required(VERSION 3.14)

project(lemonade_nexus LANGUAGES CXX)

set(BINARY_NAME "lemonade_nexus")

cmake_policy(SET CMP0063 NEW)

set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

# Configure bundle settings
set(FLUTTER_TARGET_PLATFORM "windows-x64")
set(CMAKE_CONFIGURATION_TYPES Debug;Profile;Release CACHE STRING "" FORCE)

# Profile build settings (required by Flutter CMake integration)
set(CMAKE_EXE_LINKER_FLAGS_PROFILE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_PROFILE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_RELEASE}")

# Use Unicode for all projects
add_definitions(-DUNICODE -D_UNICODE)

# Compilation settings that should be applied to most targets.
function(APPLY_STANDARD_SETTINGS TARGET)
  target_compile_features(${TARGET} PUBLIC cxx_std_17)
  target_compile_options(${TARGET} PRIVATE /W4 /WX /wd"4100")
  target_compile_options(${TARGET} PRIVATE /EHsc)
  target_compile_definitions(${TARGET} PRIVATE "IS_BUILD")
  target_link_options(${TARGET} PRIVATE "/NXCOMPAT")
  target_link_options(${TARGET} PRIVATE "/DYNAMICBASE")
  target_link_options(${TARGET} PRIVATE "/INCREMENTAL:NO")
  target_link_options(${TARGET} PRIVATE "/SUBSYSTEM:WINDOWS")
endfunction()

# Root folder
set(FLUTTER_ROOT "$ENV{FLUTTER_ROOT}")
if(NOT FLUTTER_ROOT OR FLUTTER_ROOT STREQUAL "")
  set(FLUTTER_ROOT "C:/Users/antmi/lemonade-nexus/apps/LemonadeNexus/flutter-sdk/flutter")
endif()
# Normalize path to use forward slashes (required for CMake on Windows)
file(TO_CMAKE_PATH "${FLUTTER_ROOT}" FLUTTER_ROOT)

# Set up Flutter
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")
set(FLUTTER_BIN_DIR "${FLUTTER_ROOT}/bin")

# Include the Flutter managed directory first
# This must happen before add_subdirectory(runner) because the runner depends on flutter_assemble
add_subdirectory(flutter)

# Add Flutter library (defined in flutter/CMakeLists.txt)
# Add flutter_wrapper_app library (defined in flutter/CMakeLists.txt)
# Add flutter_wrapper_plugin library (defined in flutter/CMakeLists.txt)
# Add flutter_texture_registrar library (defined in flutter/CMakeLists.txt)

# Build the SDK library
set(SDK_ROOT "${CMAKE_SOURCE_DIR}/../../projects/LemonadeNexusSDK")
set(SDK_INCLUDE "${SDK_ROOT}/include/LemonadeNexusSDK")
set(SDK_LIB "${CMAKE_SOURCE_DIR}/../build/windows/lemonade_nexus_sdk.lib")

# Add Windows-specific dependencies
list(APPEND FLUTTER_LIBRARY windows)

# Include the runner subdirectory where the actual executable is built
add_subdirectory(runner)

# Include the Flutter generated CMake config (must be after add_executable in runner)
include("${CMAKE_CURRENT_SOURCE_DIR}/flutter/generated_plugins.cmake")

# Add INSTALL target for Flutter compatibility - install to local build directory
set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/output" CACHE PATH "Install directory" FORCE)
install(TARGETS ${BINARY_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/runner")
