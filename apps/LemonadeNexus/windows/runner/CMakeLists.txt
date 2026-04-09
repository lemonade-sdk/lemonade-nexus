cmake_minimum_required(VERSION 3.14)

project(runner LANGUAGES CXX)

# Set the Flutter managed directory
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../flutter")

# Define the application target
add_executable(${BINARY_NAME} WIN32
  flutter_window.cpp
  main.cpp
  run_loop.cpp
  utils.cpp
  win32_window.cpp
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/core_implementations.cc"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/standard_codec.cc"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/flutter_engine.cc"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/flutter_view_controller.cc"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/plugin_registrar.cc"
)

# Set cpp_client_wrapper path explicitly with forward slashes
set(CPP_CLIENT_WRAPPER_DIR "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper")

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
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/include"
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
  "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release"
)

# Link the SDK library
target_link_libraries(${BINARY_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release/LemonadeNexusSDK.lib"
)

# Copy assets to output directory
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  "${CMAKE_SOURCE_DIR}/../assets"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/assets"
)

# Copy Flutter DLLs and required files to output directory
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/flutter_windows.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>"
)

add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/icudtl.dat"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>"
)

add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/libtessellator.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>"
)
