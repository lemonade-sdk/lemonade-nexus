/**
 * @file ServiceMain.cpp
 * @brief Windows Service entry point for Lemonade-Nexus
 *
 * This file provides Windows Service Control Manager (SCM) integration,
 * allowing Lemonade-Nexus to run as a background Windows Service.
 *
 * When started as a service, the SCM calls ServiceMain(). When running
 * in console mode, the regular main() in main.cpp is used.
 */

#ifdef _WIN32

#include <windows.h>
#include <spdlog/spdlog.h>
#include <string>

// Forward declaration of main() from main.cpp
extern int main(int argc, char* argv[]);

// ============================================================================
// Global Service State
// ============================================================================

static SERVICE_STATUS        g_ServiceStatus = {0};
static SERVICE_STATUS_HANDLE g_StatusHandle  = NULL;
static HANDLE                g_StopEvent     = INVALID_HANDLE_VALUE;

// ============================================================================
// Service Control Handler
// ============================================================================

/**
 * @brief Handles control requests from the Service Control Manager
 */
VOID WINAPI ServiceCtrlHandler(DWORD dwControl)
{
    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // Signal the service to stop
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCurrentState  = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwCheckPoint    = 1;
            g_ServiceStatus.dwWaitHint      = 5000; // 5 seconds

            if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus))
            {
                spdlog::error("Failed to set SERVICE_STOP_PENDING status");
            }

            // Signal the stop event
            SetEvent(g_StopEvent);
            spdlog::info("Lemonade-Nexus service stopping...");
            return;

        case SERVICE_CONTROL_PAUSE:
            g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
            spdlog::info("Lemonade-Nexus service paused");
            break;

        case SERVICE_CONTROL_CONTINUE:
            g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
            spdlog::info("Lemonade-Nexus service continuing");
            break;

        case SERVICE_CONTROL_INTERROGATE:
            // SCM is requesting current status - just return
            spdlog::debug("Service interrogate received");
            break;

        default:
            break;
    }

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ============================================================================
// Service Main Entry Point
// ============================================================================

/**
 * @brief Service entry point called by SCM
 *
 * This function is called when the Windows Service Control Manager
 * starts the Lemonade-Nexus service. It initializes the service
 * status and creates a worker thread to run the actual server logic.
 */
VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv)
{
    // Register the service control handler
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"LemonadeNexus", ServiceCtrlHandler);

    if (g_StatusHandle == NULL)
    {
        spdlog::error("Failed to register service control handler");
        return;
    }

    // Initialize service status
    ZeroMemory(&g_ServiceStatus, sizeof(SERVICE_STATUS));
    g_ServiceStatus.dwServiceType        = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    // Report SERVICE_START_PENDING
    g_ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
    g_ServiceStatus.dwAcceptedControls   = 0;
    g_ServiceStatus.dwCheckPoint         = 1;
    g_ServiceStatus.dwWaitHint           = 3000; // 3 seconds

    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus))
    {
        spdlog::error("Failed to set SERVICE_START_PENDING status");
        return;
    }

    // Create stop event for graceful shutdown
    g_StopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        spdlog::error("Failed to create stop event: {}", GetLastError());
        return;
    }

    // Report SERVICE_RUNNING
    g_ServiceStatus.dwCurrentState       = SERVICE_RUNNING;
    g_ServiceStatus.dwAcceptedControls   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
                                            SERVICE_ACCEPT_PAUSE_CONTINUE;
    g_ServiceStatus.dwCheckPoint         = 0;
    g_ServiceStatus.dwWaitHint           = 0;

    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus))
    {
        spdlog::error("Failed to set SERVICE_RUNNING status");
        return;
    }

    spdlog::info("Lemonade-Nexus service started");

    // Run the main application logic
    // Note: This runs in the service thread context
    char* args[] = { const_cast<char*>("lemonade-nexus"), nullptr };
    int result = main(1, args);

    // Report service stopped
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = (result == 0) ? 0 : 1;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    spdlog::info("Lemonade-Nexus service stopped (exit code: {})", result);

    // Cleanup
    if (g_StopEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// Windows DLL Entry Point (for service registration)
// ============================================================================

/**
 * @brief Windows DLL entry point
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            // Note: Logging not available during DLL initialization
            break;
        case DLL_PROCESS_DETACH:
            // Note: Logging may be uninitialized during DLL detach
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

#endif // _WIN32

/**
 * @page windows_service Windows Service Integration
 *
 * ## Installation
 *
 * To install the Lemonade-Nexus Windows Service:
 *
 * ```powershell
 * # Using sc.exe (built-in Windows tool)
 * sc create LemonadeNexus binPath= "C:\Program Files\Lemonade-Nexus\bin\lemonade-nexus.exe" start= auto DisplayName= "Lemonade-Nexus Mesh VPN Server"
 *
 * # Using PowerShell
 * New-Service -Name "LemonadeNexus" `
 *             -BinaryPathName "C:\Program Files\Lemonade-Nexus\bin\lemonade-nexus.exe" `
 *             -DisplayName "Lemonade-Nexus Mesh VPN Server" `
 *             -Description "Self-hosted WireGuard mesh VPN server" `
 *             -StartupType Automatic
 * ```
 *
 * ## Management
 *
 * ```powershell
 * # Start service
 * Start-Service LemonadeNexus
 *
 * # Stop service
 * Stop-Service LemonadeNexus
 *
 * # Check status
 * Get-Service LemonadeNexus
 *
 * # View logs (Windows Event Log > Applications)
 * Get-EventLog -LogName Application -Source LemonNexus -Newest 20
 * ```
 *
 * ## Uninstall
 *
 * ```powershell
 * # Stop and remove service
 * Stop-Service LemonadeNexus -Force
 * sc delete LemonadeNexus
 * ```
 */
