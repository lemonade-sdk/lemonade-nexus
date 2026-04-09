cmake_minimum_required(VERSION 3.14)

project(runner LANGUAGES CXX)

# Define the application target
add_executable(${BINARY_NAME} WIN32
  flutter_window.cpp
  main.cpp
  utils.cpp
  win32_window.cpp
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  Runner.rc
  runner.exe.manifest
)

# Apply the standard set of build settings
apply_standard_settings(${BINARY_NAME})

# Add preprocessor definitions for the build version
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

# Enable UTF-8 support
target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")
target_compile_definitions(${BINARY_NAME} PRIVATE "UNICODE" "_UNICODE")

# Include Flutter bindings
target_include_directories(${BINARY_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64"
)

# Link required libraries
target_link_libraries(${BINARY_NAME} PRIVATE
  flutter
  flutter_wrapper_app
  flutter_wrapper_plugin
  dwmapi.lib
)

# Include the FFI SDK header
target_include_directories(${BINARY_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}/../../projects/LemonadeNexusSDK/include"
)

# Link the SDK library (to be built separately)
# target_link_libraries(${BINARY_NAME} PRIVATE lemonade_nexus_sdk)
