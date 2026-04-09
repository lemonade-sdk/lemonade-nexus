// Copyright (c) 2024 Lemonade Nexus. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNNER_WIN32_WINDOW_H_
#define RUNNER_WIN32_WINDOW_H_

#include <windows.h>

#include <functional>
#include <memory>
#include <string>

// Tray icon message ID
#define WM_TRAYICON (WM_USER + 1)

// Tray icon ID
#define ID_TRAY_APP_ICON 5000

// Menu item IDs
#define ID_TRAY_CONNECT 5001
#define ID_TRAY_DISCONNECT 5002
#define ID_TRAY_DASHBOARD 5003
#define ID_TRAY_SETTINGS 5004
#define ID_TRAY_EXIT 5005

// A class abstraction for a high DPI-aware Win32 Window.
class Win32Window {
 public:
  // Point and size types for convenience.
  struct Point {
    unsigned int x;
    unsigned int y;
    Point(unsigned int x, unsigned int y) : x(x), y(y) {}
  };

  struct Size {
    unsigned int width;
    unsigned int height;
    Size(unsigned int width, unsigned int height)
        : width(width), height(height) {}
  };

  Win32Window();
  virtual ~Win32Window();

  // Creates a win32 window with the given title, origin, and size.
  bool CreateAndShow(const std::wstring& title,
                     const Point& origin,
                     const Size& size);

  // Shows the window.
  void Show();

  // Hide the window.
  void Hide();

  // Sets the quit on close behavior.
  void SetQuitOnClose(bool quit_on_close);

  // Returns true if the window is closing.
  bool IsClosing() const;

  // Dispatches messages for the window.
  LRESULT MessageHandler(HWND hwnd, UINT message, WPARAM wparam,
                         LPARAM lparam) noexcept;

  // System tray integration
  void CreateSystemTray();
  void UpdateTrayIcon(const std::wstring& tooltip);
  void ShowContextMenu(HWND hwnd);
  void RemoveSystemTray();

 protected:
  // Window handle for system tray
  HWND GetHwnd() const { return hwnd_; }

  // Registers a window class.
  static bool RegisterWindowClass(const std::wstring& class_name);

  // Unregisters a window class.
  static void UnregisterWindowClass(const std::wstring& class_name);

  // Creates the window.
  virtual bool Create(const std::wstring& title,
                      const Point& origin,
                      const Size& size);

  // Destroy the window.
  virtual void Destroy();

  // Resets the window state.
  void Reset();

  // Handle top-level window procedure.
  static LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wparam,
                                  LPARAM lparam) noexcept;

 private:
  // The window handle.
  HWND hwnd_ = nullptr;

  // The window class name.
  std::wstring window_class_ = L"LemonadeNexusWindow";

  // Whether to quit on close.
  bool quit_on_close_ = true;

  // Whether the window is closing.
  bool is_closing_ = false;

  // System tray icon data
  NOTIFYICONDATA tray_icon_data_ = {};
  bool has_tray_icon_ = false;
};

#endif  // RUNNER_WIN32_WINDOW_H_
