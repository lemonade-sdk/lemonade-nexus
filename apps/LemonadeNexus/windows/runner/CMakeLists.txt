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
  runner.rc
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

# Copy flutter_assets to output directory (required for Flutter runtime)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  "${CMAKE_SOURCE_DIR}/../build/flutter_assets"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/flutter_assets"
)

# Copy icudtl.dat to data folder (required for ICU initialization in release mode)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/icudtl.dat"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/data/"
)

# Copy Flutter DLLs and required files to output directory
# Use release flutter_windows.dll for release builds
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64-release/flutter_windows.dll"
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

# Add dependency on flutter_assemble to ensure Dart code is built
add_dependencies(${BINARY_NAME} flutter_assemble)

# Copy plugin DLLs to output directory (flatten structure)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_BINARY_DIR}/plugins/screen_retriever/Release/screen_retriever_plugin.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_BINARY_DIR}/plugins/tray_manager/Release/tray_manager_plugin.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_BINARY_DIR}/plugins/window_manager/Release/window_manager_plugin.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)

# Copy SDK DLLs to output directory
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release/lemonade_nexus.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release/libcrypto-3-x64.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release/libssl-3-x64.dll"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/"
)

# Copy app.so to data folder in output directory
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/data"
)
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_SOURCE_DIR}/../build/windows/app.so"
  "$<TARGET_FILE_DIR:${BINARY_NAME}>/data/"
)
