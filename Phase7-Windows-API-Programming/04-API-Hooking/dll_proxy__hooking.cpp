/**
 * @file dll_proxy_hooking.cpp
 * @brief Demonstrates DLL proxy hooking techniques on Windows
 *
 * This file demonstrates how to implement DLL proxy hooking, which involves
 * creating a proxy DLL that intercepts calls to a legitimate DLL. This technique
 * is commonly used for DLL hijacking and function interception.
 *
 * WARNING: This code is for educational purposes only. DLL proxy hooking
 * can destabilize the system and should only be done in controlled environments.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 -shared -o user32_proxy.dll dll_proxy_hooking.cpp -Wl,--out-implib,libuser32_proxy.a
 *
 * Red Team Applications:
 * - DLL hijacking
 * - Intercepting API calls for monitoring or modifying behavior
 * - Bypassing security mechanisms
 * - Implementing stealthy persistence
 */

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

// Log file for debugging
std::ofstream g_LogFile;

// Original DLL handle
HMODULE g_OriginalDLL = NULL;

// Original function pointers
typedef int(WINAPI *MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxAType g_OriginalMessageBoxA = NULL;

/**
 * @brief Logs a message to the log file
 *
 * @param message Message to log
 */
void Log(const std::string &message)
{
    if (g_LogFile.is_open())
    {
        g_LogFile << message << std::endl;
        g_LogFile.flush();
    }
}

/**
 * @brief Initializes the proxy DLL
 *
 * This function loads the original DLL and gets the addresses of the functions
 * we want to hook.
 *
 * @return true if initialization was successful, false otherwise
 */
bool InitializeProxy()
{
    // Open log file
    g_LogFile.open("proxy_dll.log", std::ios::out | std::ios::app);
    if (!g_LogFile.is_open())
    {
        return false;
    }

    Log("[+] Proxy DLL loaded");

    // Get the path to the system directory
    char systemDir[MAX_PATH];
    if (!GetSystemDirectoryA(systemDir, MAX_PATH))
    {
        Log("[-] Failed to get system directory");
        return false;
    }

    // Construct the path to the original DLL
    std::string originalDllPath = std::string(systemDir) + "\\user32.dll";
    Log("[+] Original DLL path: " + originalDllPath);

    // Load the original DLL
    g_OriginalDLL = LoadLibraryA(originalDllPath.c_str());
    if (!g_OriginalDLL)
    {
        Log("[-] Failed to load original DLL");
        return false;
    }

    // Get the address of the MessageBoxA function
    g_OriginalMessageBoxA = (MessageBoxAType)GetProcAddress(g_OriginalDLL, "MessageBoxA");
    if (!g_OriginalMessageBoxA)
    {
        Log("[-] Failed to get address of MessageBoxA");
        return false;
    }

    Log("[+] Original MessageBoxA address: " + std::to_string((DWORD_PTR)g_OriginalMessageBoxA));
    Log("[+] Proxy DLL initialized successfully");

    return true;
}

/**
 * @brief Our hooked version of MessageBoxA
 *
 * This function will be called instead of the original MessageBoxA.
 * It modifies the behavior by changing the message text and then
 * calls the original function.
 */
extern "C" __declspec(dllexport) int WINAPI MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // Ensure the proxy is initialized
    static bool initialized = InitializeProxy();
    if (!initialized || !g_OriginalMessageBoxA)
    {
        return 0;
    }

    // Log the interception
    Log("[-] MessageBoxA hooked via proxy!");
    Log("[-] Original text: " + std::string(lpText ? lpText : "NULL"));
    Log("[-] Original caption: " + std::string(lpCaption ? lpCaption : "NULL"));

    // Modify the parameters
    std::string newText = std::string(lpText ? lpText : "") + "\n[This message was intercepted by a proxy DLL]";
    std::string newCaption = "[PROXY HOOKED] " + std::string(lpCaption ? lpCaption : "");

    // Call the original function with our modified parameters
    int result = g_OriginalMessageBoxA(hWnd, newText.c_str(), newCaption.c_str(), uType);

    Log("[-] MessageBoxA call completed with result: " + std::to_string(result));

    return result;
}

/**
 * @brief DLL entry point
 *
 * This function is called when the DLL is loaded or unloaded.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize the proxy when the DLL is loaded
        DisableThreadLibraryCalls(hinstDLL);
        break;

    case DLL_PROCESS_DETACH:
        // Clean up when the DLL is unloaded
        if (g_LogFile.is_open())
        {
            g_LogFile << "[+] Proxy DLL unloaded" << std::endl;
            g_LogFile.close();
        }

        if (g_OriginalDLL)
        {
            FreeLibrary(g_OriginalDLL);
        }
        break;
    }

    return TRUE;
}

/**
 * @brief Export all other functions from the original DLL
 *
 * In a real proxy DLL, you would need to export all functions from the original DLL.
 * This is typically done using a .def file or by dynamically creating forwarders.
 * For simplicity, this example only hooks MessageBoxA.
 */
