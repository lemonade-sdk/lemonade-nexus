// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_loop.h"

#include <windows.h>

#include <algorithm>

RunLoop::RunLoop() {}

RunLoop::~RunLoop() {}

void RunLoop::Run() {
  bool keep_running = true;
  while (keep_running) {
    ProcessMessages();

    // Wait for the next event.
    MSG msg;
    if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
      if (msg.message == WM_QUIT) {
        keep_running = false;
      } else {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }
    } else {
      // No pending messages, so wait for the next Flutter frame.
      ProcessEvents();
    }
  }
}

void RunLoop::RegisterFlutterInstance(
    flutter::FlutterEngine* flutter_instance) {
  flutter_instances_.insert(flutter_instance);
}

void RunLoop::UnregisterFlutterInstance(
    flutter::FlutterEngine* flutter_instance) {
  flutter_instances_.erase(flutter_instance);
}

void RunLoop::ProcessMessages() {
  MSG msg;
  while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
    if (msg.message == WM_QUIT) {
      return;
    }
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
}

std::chrono::milliseconds RunLoop::ProcessEvents() {
  // Let Flutter handle the event processing.
  for (auto* instance : flutter_instances_) {
    instance->ProcessMessages();
  }

  // Return a default wait time.
  return std::chrono::milliseconds(10);
}
