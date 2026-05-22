cmake_minimum_required(VERSION 3.14)

project(runner LANGUAGES CXX)

# Set the Flutter managed directory
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../flutter")

# Define the application target
add_executable(${BINARY_NAME} WIN32
  flutter_window.cpp
  main.cpp
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

set(CPP_CLIENT_WRAPPER_DIR "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper")

apply_standard_settings(${BINARY_NAME})

target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")
target_compile_definitions(${BINARY_NAME} PRIVATE "UNICODE" "_UNICODE")

target_include_directories(${BINARY_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64"
  "${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/cpp_client_wrapper/include"
)

target_link_libraries(${BINARY_NAME} PRIVATE
  flutter
  flutter_wrapper_app
  flutter_wrapper_plugin
  dwmapi.lib
)

# =========================================================================
# SDK Library Configuration - FFI Only
# =========================================================================

set(SDK_RELEASE_DIR "${CMAKE_SOURCE_DIR}/../../../build/projects/LemonadeNexusSDK/Release")

if(EXISTS "${SDK_RELEASE_DIR}/lemonade_nexus.h")
  target_include_directories(${BINARY_NAME} PRIVATE "${SDK_RELEASE_DIR}")
  message(STATUS "Found SDK headers at ${SDK_RELEASE_DIR}")
else()
  message(WARNING "SDK headers not found at ${SDK_RELEASE_DIR}")
endif()

# =========================================================================
# Post-Build: Use cmake -E echo + conditional copies via cmake script
# CMake 3.31 supports $<IF:$<EXISTS:...>,...> generator expressions
# =========================================================================

add_dependencies(${BINARY_NAME} flutter_assemble)

set(OUT_DIR "$<TARGET_FILE_DIR:${BINARY_NAME}>")

# Create a post-build script that conditionally copies files
set(POST_BUILD_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/post_build.cmake")

add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND}
    -DOUT_DIR=${OUT_DIR}
    -DFLUTTER_ROOT=${FLUTTER_ROOT}
    -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBINARY_DIR=${CMAKE_BINARY_DIR}
    -DSDK_RELEASE_DIR=${SDK_RELEASE_DIR}
    -P ${POST_BUILD_SCRIPT}
  COMMENT "Running post-build copy step"
)
