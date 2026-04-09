cmake_minimum_required(VERSION 3.14)

project(lemonade_nexus LANGUAGES CXX)

set(BINARY_NAME "lemonade_nexus")

cmake_policy(SET CMP0063 NEW)

set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

# Configure bundle settings
set(FLUTTER_TARGET_PLATFORM "windows-x64")

# Root folder
set(FLUTTER_ROOT "$ENV{FLUTTER_ROOT}")
if(NOT FLUTTER_ROOT)
  set(FLUTTER_ROOT "C:/src/flutter")
endif()

include("${FLUTTER_ROOT}/packages/flutter_tools/bin/tool_backend.bat")

# Build the SDK library
set(SDK_ROOT "${CMAKE_SOURCE_DIR}/../../projects/LemonadeNexusSDK")
set(SDK_INCLUDE "${SDK_ROOT}/include/LemonadeNexusSDK")
set(SDK_LIB "${CMAKE_SOURCE_DIR}/lemonade_nexus_sdk.lib")

# Add Windows-specific dependencies
list(APPEND FLUTTER_LIBRARY windows)

# Include the Flutter generated CMake config
include("${CMAKE_CURRENT_SOURCE_DIR}/../flutter/generated_plugins.cmake")

# Main runner sources
add_executable(${BINARY_NAME} WIN32
  "flutter_windows_dll.cc"
  "main.cpp"
  "run_loop.cpp"
  "utils.cpp"
  "win32_window.cpp"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Apply the standard set of build settings
apply_standard_settings(${BINARY_NAME})

# Add preprocessor definitions
target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")

# Add include paths
target_include_directories(${BINARY_NAME} PRIVATE
  "${SDK_INCLUDE}"
)

# Link libraries
target_link_libraries(${BINARY_NAME} PRIVATE
  flutter_wrapper_app
  ${SDK_LIB}
)

# Add dependency on plugins
target_link_libraries(${BINARY_NAME} PRIVATE
  flutter_texture_registrar
)

# Enable UTF-8 support
target_compile_definitions(${BINARY_NAME} PRIVATE "UNICODE" "_UNICODE")

# Generate the windows asset bundle
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  "${CMAKE_SOURCE_DIR}/assets"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/assets"
)
