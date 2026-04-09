// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNNER_UTILS_H_
#define RUNNER_UTILS_H_

#include <string>
#include <vector>

// Creates a console for the process, and redirects stdout and stderr to
// it for both the runner and the Flutter library.
void CreateAndAttachConsole();

// Converts a UTF-16 string to UTF-8.
std::string Utf8FromUtf16(const wchar_t* utf16);

// Converts a UTF-8 string to UTF-16.
std::wstring Utf16FromUtf8(const char* utf8);

// Returns the command line arguments.
std::vector<std::string> GetCommandLineArguments();

#endif  // RUNNER_UTILS_H_
