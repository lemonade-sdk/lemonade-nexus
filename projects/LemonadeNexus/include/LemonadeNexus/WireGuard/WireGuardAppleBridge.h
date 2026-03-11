#pragma once

/// @file WireGuardAppleBridge.h
/// C-callable bridge for wireguard-go on Apple platforms.
///
/// Provides utun device creation (macOS kernel API) and thin wrappers around
/// the wireguard-go C functions exported by WireGuardKitGo.
///
/// All functions are safe to call from C++ (extern "C" linkage).

#ifdef __cplusplus
extern "C" {
#endif

/// Create a macOS utun device.
///
/// @param[out] iface_name  Buffer to receive the interface name (e.g. "utun3").
/// @param      name_len    Size of iface_name buffer (should be >= 16).
/// @return     The utun file descriptor on success, or -1 on failure.
int wg_apple_create_utun(char* iface_name, unsigned long name_len);

/// Close a utun device.
///
/// @param tun_fd  File descriptor returned by wg_apple_create_utun().
void wg_apple_close_utun(int tun_fd);

/// Start a wireguard-go tunnel on the given utun.
///
/// @param iface_name  Interface name (e.g. "utun3").
/// @param settings    WireGuard config in wireguard-go "UAPI" format.
/// @param tun_fd      File descriptor for the utun device.
/// @return            A handle (>= 0) on success, or -1 on failure.
int wg_apple_turn_on(const char* iface_name, const char* settings, int tun_fd);

/// Stop a running wireguard-go tunnel.
///
/// @param handle  Handle returned by wg_apple_turn_on().
void wg_apple_turn_off(int handle);

/// Update the configuration of a running tunnel.
///
/// @param handle    Handle returned by wg_apple_turn_on().
/// @param settings  New WireGuard config in UAPI format.
/// @return          0 on success, or an error code.
long long wg_apple_set_config(int handle, const char* settings);

/// Get the current configuration of a running tunnel.
///
/// @param handle  Handle returned by wg_apple_turn_on().
/// @return        Config string (caller must free with wg_apple_free_config),
///                or NULL on failure.
char* wg_apple_get_config(int handle);

/// Free a config string returned by wg_apple_get_config().
void wg_apple_free_config(char* config);

/// Get the wireguard-go version string.
///
/// @return  Static version string (do NOT free).
const char* wg_apple_version(void);

/// Assign an IP address (CIDR) to a network interface.
///
/// Uses the ifconfig command on macOS.
///
/// @param iface_name  Interface name (e.g. "utun3").
/// @param address     CIDR address (e.g. "10.64.0.1/32").
/// @return            0 on success, -1 on failure.
int wg_apple_set_address(const char* iface_name, const char* address);

/// Add a route for a subnet via a network interface.
///
/// @param destination  CIDR destination (e.g. "10.128.0.0/24").
/// @param iface_name   Interface name (e.g. "utun3").
/// @return             0 on success, -1 on failure.
int wg_apple_add_route(const char* destination, const char* iface_name);

#ifdef __cplusplus
}
#endif
