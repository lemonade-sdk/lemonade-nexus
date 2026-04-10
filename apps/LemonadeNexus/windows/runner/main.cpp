// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>

#include <memory>
#include <string>
#include <vector>
#include <windows.h>

#include "flutter_window.h"
#include "run_loop.h"
#include "utils.h"
#include "win32_window.h"

namespace {

// The title of the window
constexpr const wchar_t* kWindowTitle = L"Lemonade Nexus";

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running as a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  // Get the executable path to build the data directory path
  wchar_t exe_path[MAX_PATH];
  GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

  // Extract directory from executable path
  std::wstring exe_dir(exe_path);
  size_t last_slash = exe_dir.find_last_of(L"\\");
  if (last_slash != std::wstring::npos) {
    exe_dir = exe_dir.substr(0, last_slash);
  }
  std::wstring data_path = exe_dir + L"\\data";

  // Initialize the Flutter engine
  auto run_loop = std::make_unique<RunLoop>();
  flutter::DartProject project(data_path.c_str());

  std::vector<std::string> arguments;
  arguments.push_back("--disable-dart-profile");

  const wchar_t* target_platform = L"--target-platform=windows-x64";
  arguments.push_back(Utf8FromUtf16(target_platform));

  project.set_dart_entrypoint_arguments(std::move(arguments));

  FlutterWindow window(run_loop.get(), std::move(project));
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);

  if (!window.CreateAndShow(kWindowTitle, origin, size)) {
    return EXIT_FAILURE;
  }

  window.SetQuitOnClose(true);

  // Create system tray icon
  window.CreateSystemTray();

  run_loop->Run();

  // Clean up system tray
  window.RemoveSystemTray();

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
