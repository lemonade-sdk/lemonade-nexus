// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "win32_window.h"

#include <flutter_windows.h>
#include <dwmapi.h>

#include "resource.h"

namespace {

/// Window attribute that enables dark mode window decorations.
///
/// Redefined in case the developer's machine has a Windows SDK newer than
/// the one used to build this file.
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

constexpr const wchar_t kWindowClassName[] = L"FLUTTER_RUNNER_WIN32_WINDOW";

/// The number of Win32 Window objects that can exist at the same time is 10.
/// We don't expect to have more than one window per process, but this is a
/// reasonable limit.
constexpr int kMaxWindows = 10;

/// Registry key for app theme preference.
///
/// A value of 0 indicates apps should use dark mode. A non-zero or missing
/// value indicates apps should use light mode.
constexpr const wchar_t kGetPreferredBrightnessRegKey[] =
  L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
constexpr const wchar_t kGetPreferredBrightnessRegValue[] = L"AppsUseLightTheme";

// The number of NDIS timers to use for the window.
// This is taken from the Flutter reference implementation.
constexpr int kNumTimers = 1;

}  // namespace

// Global window count
int g_active_window_count = 0;

Win32Window::Win32Window() {
  ++g_active_window_count;
}

Win32Window::~Win32Window() {
  --g_active_window_count;
  Destroy();
}

bool Win32Window::CreateAndShow(const std::wstring& title,
                                const Point& origin,
                                const Size& size) {
  Destroy();

  const POINT target_point = {static_cast<LONG>(origin.x),
                              static_cast<LONG>(origin.y)};
  HMONITOR monitor = MonitorFromPoint(target_point, MONITOR_DEFAULTTONEAREST);
  UINT dpi = FlutterDesktopGetDpiForMonitor(monitor);
  double scale_factor = dpi / 96.0;

  HWND window = CreateWindow(
      kWindowClassName, title.c_str(),
      WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT,
      static_cast<int>(size.width * scale_factor),
      static_cast<int>(size.height * scale_factor),
      nullptr, nullptr, GetModuleHandle(nullptr), this);

  if (!window) {
    return false;
  }

  return OnCreate();
}

bool Win32Window::Show() {
  return ShowWindow(hwnd_, SW_SHOWNORMAL);
}

bool Win32Window::Hide() {
  return ShowWindow(hwnd_, SW_HIDE);
}

void Win32Window::SetQuitOnClose(bool quit_on_close) {
  quit_on_close_ = quit_on_close;
}

bool Win32Window::IsClosing() const {
  return is_closing_;
}

LRESULT Win32Window::MessageHandler(HWND hwnd, UINT message, WPARAM wparam,
                                    LPARAM lparam) noexcept {
  switch (message) {
    case WM_DESTROY:
      is_closing_ = true;
      return 0;

    case WM_TRAYICON:
      // Handle tray icon messages
      switch (LOWORD(lparam)) {
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
          ShowContextMenu(hwnd);
          break;
        case WM_LBUTTONDBLCLK:
          // Double-click to restore window
          Show();
          SetForegroundWindow(hwnd);
          break;
      }
      return 0;

    case WM_DPICHANGED: {
      auto newRectSize = reinterpret_cast<RECT*>(lparam);
      LONG newWidth = newRectSize->right - newRectSize->left;
      LONG newHeight = newRectSize->bottom - newRectSize->top;

      SetWindowPos(hwnd, nullptr, newRectSize->left, newRectSize->top, newWidth,
                   newHeight, SWP_NOZORDER | SWP_NOACTIVATE);

      return TRUE;
    }
    case WM_SIZE: {
      RECT rect = GetClientArea();
      if (child_content_ != nullptr) {
        MoveWindow(child_content_, rect.left, rect.top, rect.right - rect.left,
                   rect.bottom - rect.top, TRUE);
      }
      return 0;
    }

    case WM_ACTIVATE:
      if (child_content_ != nullptr) {
        SetFocus(child_content_);
      }
      return 0;

    case WM_DWMCOLORIZATIONCOLORCHANGED:
      UpdateTheme();
      return 0;
  }

  return DefWindowProc(hwnd, message, wparam, lparam);
}

void Win32Window::Destroy() {
  if (hwnd_) {
    DestroyWindow(hwnd_);
    hwnd_ = nullptr;
  }
  if (g_active_window_count == 0) {
    UnregisterWindowClass(kWindowClassName);
  }
}

void Win32Window::Reset() {
  hwnd_ = nullptr;
  is_closing_ = false;
}

bool Win32Window::RegisterWindowClass(const std::wstring& class_name) {
  WNDCLASS window_class{};
  window_class.hCursor = LoadCursor(nullptr, IDC_ARROW);
  window_class.lpszClassName = class_name.c_str();
  window_class.style = CS_HREDRAW | CS_VREDRAW;
  window_class.cbClsExtra = 0;
  window_class.cbWndExtra = 0;
  window_class.hInstance = GetModuleHandle(nullptr);
  window_class.hIcon =
      LoadIcon(window_class.hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
  window_class.hbrBackground = 0;
  window_class.lpszMenuName = nullptr;
  window_class.lpfnWndProc = WndProc;
  RegisterClass(&window_class);
  return true;
}

void Win32Window::UnregisterWindowClass(const std::wstring& class_name) {
  UnregisterClass(class_name.c_str(), nullptr);
}

bool Win32Window::Create(const std::wstring& title,
                         const Point& origin,
                         const Size& size) {
  if (!RegisterWindowClass(kWindowClassName)) {
    return false;
  }

  const POINT target_point = {static_cast<LONG>(origin.x),
                              static_cast<LONG>(origin.y)};
  HMONITOR monitor = MonitorFromPoint(target_point, MONITOR_DEFAULTTONEAREST);
  UINT dpi = FlutterDesktopGetDpiForMonitor(monitor);
  double scale_factor = dpi / 96.0;

  HWND window = CreateWindow(
      kWindowClassName, title.c_str(),
      WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT,
      static_cast<int>(size.width * scale_factor),
      static_cast<int>(size.height * scale_factor),
      nullptr, nullptr, GetModuleHandle(nullptr), this);

  if (!window) {
    return false;
  }

  UpdateTheme();

  return OnCreate();
}

// static
LRESULT CALLBACK Win32Window::WndProc(HWND hwnd, UINT message, WPARAM wparam,
                                      LPARAM lparam) noexcept {
  if (message == WM_NCCREATE) {
    auto window_struct = reinterpret_cast<CREATESTRUCT*>(lparam);
    SetWindowLongPtr(hwnd, GWLP_USERDATA,
                     reinterpret_cast<LONG_PTR>(window_struct->lpCreateParams));

    auto that = static_cast<Win32Window*>(window_struct->lpCreateParams);
    that->EnableDarkMode();
    that->hwnd_ = hwnd;

    return TRUE;
  }

  auto that = reinterpret_cast<Win32Window*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
  if (that) {
    return that->MessageHandler(hwnd, message, wparam, lparam);
  }

  return DefWindowProc(hwnd, message, wparam, lparam);
}

bool Win32Window::OnCreate() {
  // Enable dark mode for the window
  EnableDarkMode();
  return true;
}

void Win32Window::OnDestroy() {
  // Cleanup on destroy
  RemoveSystemTray();
}

// =========================================================================
// System Tray Implementation
// =========================================================================

void Win32Window::UpdateTheme() {
  BOOL is_dark_mode = false;
  DWORD reg_value = 0;
  DWORD size = sizeof(reg_value);

  if (RegGetValueW(HKEY_CURRENT_USER, kGetPreferredBrightnessRegKey,
                   kGetPreferredBrightnessRegValue,
                   RRF_RT_REG_DWORD, nullptr, &reg_value, &size) ==
      ERROR_SUCCESS) {
    is_dark_mode = (reg_value == 0);
  }

  if (hwnd_) {
    DwmSetWindowAttribute(hwnd_, DWMWA_USE_IMMERSIVE_DARK_MODE, &is_dark_mode,
                          sizeof(is_dark_mode));
  }
}

void Win32Window::EnableDarkMode() {
  if (!hwnd_) {
    return;
  }

  BOOL is_dark_mode = FALSE;
  DWORD reg_value = 0;
  DWORD size = sizeof(reg_value);

  if (RegGetValueW(HKEY_CURRENT_USER, kGetPreferredBrightnessRegKey,
                   kGetPreferredBrightnessRegValue,
                   RRF_RT_REG_DWORD, nullptr, &reg_value, &size) ==
      ERROR_SUCCESS) {
    is_dark_mode = (reg_value == 0);
  }

  if (is_dark_mode) {
    DwmSetWindowAttribute(hwnd_, DWMWA_USE_IMMERSIVE_DARK_MODE, &is_dark_mode,
                          sizeof(is_dark_mode));
  }
}

RECT Win32Window::GetClientArea() const {
  RECT rect = {0, 0, 0, 0};
  if (hwnd_) {
    GetClientRect(hwnd_, &rect);
  }
  return rect;
}

void Win32Window::SetChildContent(HWND child_content) {
  child_content_ = child_content;
  if (hwnd_ && child_content_) {
    RECT rect = GetClientArea();
    MoveWindow(child_content_, rect.left, rect.top, rect.right - rect.left,
               rect.bottom - rect.top, TRUE);
    ShowWindow(child_content_, SW_SHOW);
  }
}

// =========================================================================
// System Tray Implementation
// =========================================================================

void Win32Window::CreateSystemTray() {
  if (has_tray_icon_) {
    return;
  }

  // Load the application icon
  HICON icon = LoadIcon(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDI_APP_ICON));
  if (!icon) {
    // Fallback to default icon
    icon = LoadIcon(nullptr, IDI_APPLICATION);
  }

  // Use Shell_NotifyIconW directly with local structure
  NOTIFYICONDATAW nid = {};
  nid.cbSize = sizeof(NOTIFYICONDATAW);
  nid.hWnd = hwnd_;
  nid.uID = ID_TRAY_APP_ICON;
  nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  nid.uCallbackMessage = WM_TRAYICON;
  nid.hIcon = icon;

  // Set initial tooltip
  wcscpy_s(nid.szTip, ARRAYSIZE(nid.szTip), L"Lemonade Nexus VPN");

  // Add the icon
  if (Shell_NotifyIconW(NIM_ADD, &nid)) {
    has_tray_icon_ = true;
    // Copy back to raw storage if needed
    memcpy(tray_icon_data_raw_, &nid, sizeof(nid));
  }
}

void Win32Window::UpdateTrayIcon(const std::wstring& tooltip) {
  if (!has_tray_icon_) {
    return;
  }

  NOTIFYICONDATAW nid = {};
  nid.cbSize = sizeof(NOTIFYICONDATAW);
  nid.hWnd = hwnd_;
  nid.uID = ID_TRAY_APP_ICON;
  nid.uFlags = NIF_TIP;
  nid.uCallbackMessage = WM_TRAYICON;

  // Set tooltip
  wcscpy_s(nid.szTip, ARRAYSIZE(nid.szTip), tooltip.c_str());

  Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void Win32Window::ShowContextMenu(HWND hwnd) {
  // Create the context menu
  HMENU menu = CreatePopupMenu();

  // Add menu items
  AppendMenu(menu, MF_STRING, ID_TRAY_CONNECT, L"Connect");
  AppendMenu(menu, MF_STRING, ID_TRAY_DISCONNECT, L"Disconnect");
  AppendMenu(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenu(menu, MF_STRING, ID_TRAY_DASHBOARD, L"Open Dashboard");
  AppendMenu(menu, MF_STRING, ID_TRAY_SETTINGS, L"Settings");
  AppendMenu(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenu(menu, MF_STRING, ID_TRAY_EXIT, L"Exit");

  // Get the current cursor position
  POINT pt;
  GetCursorPos(&pt);

  // Track the menu and get the selected item
  SetForegroundWindow(hwnd);
  UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, nullptr);

  // Send the command to the window
  if (cmd != 0) {
    PostMessage(hwnd, WM_COMMAND, cmd, 0);
  }

  DestroyMenu(menu);
}

void Win32Window::RemoveSystemTray() {
  if (has_tray_icon_) {
    NOTIFYICONDATAW nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = hwnd_;
    nid.uID = ID_TRAY_APP_ICON;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    has_tray_icon_ = false;
  }
}
