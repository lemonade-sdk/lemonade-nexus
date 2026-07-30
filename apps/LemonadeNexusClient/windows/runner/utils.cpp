// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "utils.h"

#include <flutter_windows.h>
#include <io.h>
#include <stdio.h>
#include <windows.h>

#include <iostream>

void CreateAndAttachConsole() {
  if (::AllocConsole()) {
    FILE *unused;
    if (freopen_s(&unused, "CONOUT$", "w", stdout)) {
      _dup2(_fileno(stdout), 1);
    }
    if (freopen_s(&unused, "CONOUT$", "w", stderr)) {
      _dup2(_fileno(stdout), 2);
    }
    std::ios::sync_with_stdio();
    FlutterDesktopResyncOutputStreams();
  }
}

std::string Utf8FromUtf16(const wchar_t* utf16) {
  if (utf16 == nullptr) {
    return std::string();
  }
  int target_length = ::WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, utf16, -1, nullptr, 0, nullptr, nullptr);
  if (target_length == 0) {
    return std::string();
  }
  std::string utf8_string;
  utf8_string.resize(target_length);
  int converted_length = ::WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, utf16, -1, utf8_string.data(),
      target_length, nullptr, nullptr);
  if (converted_length == 0) {
    return std::string();
  }
  // Remove the null terminator from the string
  utf8_string.pop_back();
  return utf8_string;
}

std::wstring Utf16FromUtf8(const char* utf8) {
  if (utf8 == nullptr) {
    return std::wstring();
  }
  int target_length = ::MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, nullptr, 0);
  if (target_length == 0) {
    return std::wstring();
  }
  std::wstring utf16_string;
  utf16_string.resize(target_length);
  int converted_length = ::MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, utf16_string.data(),
      target_length);
  if (converted_length == 0) {
    return std::wstring();
  }
  // Remove the null terminator from the string
  utf16_string.pop_back();
  return utf16_string;
}

std::vector<std::string> GetCommandLineArguments() {
  // GetCommandLineW returns the command line as a single string.
  // This function splits it into individual arguments.
  int argc;
  wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
  if (argv == nullptr) {
    return std::vector<std::string>();
  }

  std::vector<std::string> args;
  for (int i = 0; i < argc; ++i) {
    args.push_back(Utf8FromUtf16(argv[i]));
  }

  ::LocalFree(argv);
  return args;
}
