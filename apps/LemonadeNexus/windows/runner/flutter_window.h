// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNNER_FLUTTER_WINDOW_H_
#define RUNNER_FLUTTER_WINDOW_H_

#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>

#include <memory>
#include <string>

#include "run_loop.h"
#include "win32_window.h"

// A window that does nothing but host a Flutter view.
class FlutterWindow : public Win32Window {
 public:
  // Creates a new FlutterWindow hosting a Flutter view running |project|.
  explicit FlutterWindow(RunLoop* run_loop,
                         flutter::DartProject project);
  virtual ~FlutterWindow();

 protected:
  // Win32Window:
  bool OnCreate() override;
  void OnDestroy() override;
  LRESULT MessageHandler(HWND window, UINT const message, WPARAM const wparam,
                         LPARAM const lparam) noexcept override;

 private:
  // The run loop for the Flutter engine.
  RunLoop* run_loop_;

  // The Flutter project to run.
  flutter::DartProject project_;

  // The Flutter view controller.
  std::unique_ptr<flutter::FlutterViewController> flutter_controller_;

  // Command line arguments for Dart entrypoint.
  std::vector<std::string> command_line_arguments_;
};

#endif  // RUNNER_FLUTTER_WINDOW_H_
