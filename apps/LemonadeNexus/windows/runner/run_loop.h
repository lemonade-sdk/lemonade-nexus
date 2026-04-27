// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNNER_RUN_LOOP_H_
#define RUNNER_RUN_LOOP_H_

#include <flutter/flutter_engine.h>

#include <chrono>
#include <set>
#include <vector>

// A runloop that will service events from Flutter as well as native
// messages.
class RunLoop {
 public:
  RunLoop();
  ~RunLoop();

  // Runs the runloop until the application quits.
  void Run();

  // Registers the given Flutter instance for event servicing.
  void RegisterFlutterInstance(
      flutter::FlutterEngine* flutter_instance);

  // Unregisters the given Flutter instance.
  void UnregisterFlutterInstance(
      flutter::FlutterEngine* flutter_instance);

 private:
  using TimePoint = std::chrono::steady_clock::time_point;

  // Processes all currently pending messages.
  void ProcessMessages();

  // Returns the time until the next scheduled event, or a large duration
  // if there are no pending events.
  std::chrono::milliseconds ProcessEvents();

  // All Flutter instances that need to be serviced.
  std::set<flutter::FlutterEngine*> flutter_instances_;
};

#endif  // RUNNER_RUN_LOOP_H_
