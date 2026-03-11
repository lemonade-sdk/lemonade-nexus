/// @file WireGuardAppleBridge.mm
/// Obj-C++ implementation of the Apple WireGuard bridge.
///
/// Creates macOS utun devices via the kernel control API and wraps the
/// wireguard-go C functions from WireGuardKitGo (libwg-go.a).

#import <LemonadeNexus/WireGuard/WireGuardAppleBridge.h>

#ifdef HAS_WIREGUARDKIT

#import <libwg-go.h>  // wireguard-go C-archive header

#import <sys/socket.h>
#import <sys/ioctl.h>
#import <sys/kern_control.h>
#import <sys/sys_domain.h>
#import <net/if_utun.h>
#import <unistd.h>
#import <cstring>
#import <cstdlib>
#import <cstdio>
#import <sstream>

// ---------------------------------------------------------------------------
// utun device management
// ---------------------------------------------------------------------------

int wg_apple_create_utun(char* iface_name, unsigned long name_len) {
    // Create a system control socket
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -1;
    }

    // Look up the utun control
    struct ctl_info info = {};
    std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);

    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        close(fd);
        return -1;
    }

    // Connect to allocate a utun device (unit 0 = auto-assign)
    struct sockaddr_ctl addr = {};
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;  // Let the kernel assign the next available unit

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    // Get the assigned interface name
    if (iface_name && name_len > 0) {
        socklen_t opt_len = static_cast<socklen_t>(name_len);
        if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                       iface_name, &opt_len) < 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

void wg_apple_close_utun(int tun_fd) {
    if (tun_fd >= 0) {
        close(tun_fd);
    }
}

// ---------------------------------------------------------------------------
// wireguard-go tunnel management
// ---------------------------------------------------------------------------

int wg_apple_turn_on(const char* iface_name, const char* settings, int tun_fd) {
    if (!iface_name || !settings || tun_fd < 0) {
        return -1;
    }
    return wgTurnOn(
        const_cast<char*>(iface_name),
        const_cast<char*>(settings),
        static_cast<int32_t>(tun_fd)
    );
}

void wg_apple_turn_off(int handle) {
    if (handle >= 0) {
        wgTurnOff(static_cast<int32_t>(handle));
    }
}

long long wg_apple_set_config(int handle, const char* settings) {
    if (!settings || handle < 0) {
        return -1;
    }
    return static_cast<long long>(
        wgSetConfig(static_cast<int32_t>(handle), const_cast<char*>(settings))
    );
}

char* wg_apple_get_config(int handle) {
    if (handle < 0) {
        return nullptr;
    }
    return wgGetConfig(static_cast<int32_t>(handle));
}

void wg_apple_free_config(char* config) {
    if (config) {
        free(config);
    }
}

const char* wg_apple_version(void) {
    return wgVersion();
}

// ---------------------------------------------------------------------------
// Network helpers (macOS ifconfig / route)
// ---------------------------------------------------------------------------

int wg_apple_set_address(const char* iface_name, const char* address) {
    if (!iface_name || !address) {
        return -1;
    }

    // Parse CIDR: extract the IP part before the /
    std::string addr_str(address);
    auto slash = addr_str.find('/');
    if (slash == std::string::npos) {
        return -1;
    }
    std::string ip = addr_str.substr(0, slash);

    // On macOS, point-to-point interface: ifconfig <iface> inet <ip> <ip> up
    std::ostringstream cmd;
    cmd << "ifconfig " << iface_name
        << " inet " << ip << " " << ip
        << " up 2>/dev/null";

    int ret = system(cmd.str().c_str());
    return (ret == 0) ? 0 : -1;
}

int wg_apple_add_route(const char* destination, const char* iface_name) {
    if (!destination || !iface_name) {
        return -1;
    }

    // Parse CIDR
    std::string dest_str(destination);
    auto slash = dest_str.find('/');
    if (slash == std::string::npos) {
        return -1;
    }

    std::ostringstream cmd;
    cmd << "route -n add -net " << destination
        << " -interface " << iface_name
        << " 2>/dev/null";

    int ret = system(cmd.str().c_str());
    return (ret == 0) ? 0 : -1;
}

#else // !HAS_WIREGUARDKIT

// ---------------------------------------------------------------------------
// Stubs when WireGuardKit is not available
// ---------------------------------------------------------------------------

int wg_apple_create_utun(char*, unsigned long) { return -1; }
void wg_apple_close_utun(int) {}
int wg_apple_turn_on(const char*, const char*, int) { return -1; }
void wg_apple_turn_off(int) {}
long long wg_apple_set_config(int, const char*) { return -1; }
char* wg_apple_get_config(int) { return nullptr; }
void wg_apple_free_config(char*) {}
const char* wg_apple_version(void) { return "unavailable"; }
int wg_apple_set_address(const char*, const char*) { return -1; }
int wg_apple_add_route(const char*, const char*) { return -1; }

#endif // HAS_WIREGUARDKIT
