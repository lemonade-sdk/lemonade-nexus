# post_build.cmake - Conditional file/directory copy script
# Called from runner CMakeLists.txt with variables:
#   OUT_DIR, FLUTTER_ROOT, SOURCE_DIR, BINARY_DIR, SDK_RELEASE_DIR

# Helper: copy file only if source exists
macro(copy_file SRC DEST)
  if(EXISTS "${SRC}")
    file(COPY "${SRC}" DESTINATION "${DEST}")
  endif()
endmacro()

# Helper: copy directory only if source exists
macro(copy_dir SRC DEST)
  if(EXISTS "${SRC}")
    file(COPY "${SRC}" DESTINATION "${DEST}")
  endif()
endmacro()

# Copy assets
copy_dir("${SOURCE_DIR}/../assets" "${OUT_DIR}/")

# Copy flutter_assets
copy_dir("${SOURCE_DIR}/../build/flutter_assets" "${OUT_DIR}/")

# Copy icudtl.dat
copy_file("${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/icudtl.dat" "${OUT_DIR}/data/")
copy_file("${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/icudtl.dat" "${OUT_DIR}/")

# Copy flutter_windows.dll (release)
copy_file("${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64-release/flutter_windows.dll" "${OUT_DIR}/")

# Copy libtessellator.dll
copy_file("${FLUTTER_ROOT}/bin/cache/artifacts/engine/windows-x64/libtessellator.dll" "${OUT_DIR}/")

# Copy plugin DLLs
copy_file("${BINARY_DIR}/plugins/screen_retriever/Release/screen_retriever_plugin.dll" "${OUT_DIR}/")
copy_file("${BINARY_DIR}/plugins/tray_manager/Release/tray_manager_plugin.dll" "${OUT_DIR}/")
copy_file("${BINARY_DIR}/plugins/window_manager/Release/window_manager_plugin.dll" "${OUT_DIR}/")

# Copy SDK DLLs
copy_file("${SDK_RELEASE_DIR}/lemonade_nexus.dll" "${OUT_DIR}/")
copy_file("${SDK_RELEASE_DIR}/libcrypto-3-x64.dll" "${OUT_DIR}/")
copy_file("${SDK_RELEASE_DIR}/libssl-3-x64.dll" "${OUT_DIR}/")

# Copy app.so
copy_file("${SOURCE_DIR}/../build/windows/app.so" "${OUT_DIR}/data/")
