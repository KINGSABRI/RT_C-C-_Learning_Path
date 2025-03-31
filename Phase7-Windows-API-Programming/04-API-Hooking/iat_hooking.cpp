/**
 * @file iat_hooking.cpp
 * @brief Demonstrates Import Address Table (IAT) hooking techniques on Windows
 *
 * This file demonstrates how to implement IAT hooking, which involves
 * modifying the Import Address Table of a process to redirect API calls
 * to our hook functions. This is a common technique used in security research,
 * malware analysis, and reverse engineering.
 *
 * WARNING: This code is for educational purposes only. Hooking system APIs
 * can destabilize the system and should only be done in controlled environments.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 iat_hooking.cpp -o iat_hooking.exe
 *
 * Red Team Applications:
 * - Intercepting API calls for monitoring or modifying behavior
 * - Bypassing security mechanisms
 * - Implementing stealthy persistence
 * - Hiding malicious activity
 */

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

// Define the prototype of the function we want to hook
typedef int(WINAPI *MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);

// Store the original function pointer
MessageBoxAType g_OriginalMessageBoxA = nullptr;

/**
 * @brief Our hook function that will replace MessageBoxA
 *
 * This function will be called instead of the original MessageBoxA.
 * It modifies the behavior by changing the message text and then
 * calls the original function.
 */
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // Print information about the intercepted call
    std::cout << "[-] MessageBoxA hooked via IAT!" << std::endl;
    std::cout << "[-] Original text: " << lpText << std::endl;
    std::cout << "[-] Original caption: " << lpCaption << std::endl;

    // Modify the parameters
    std::string newText = std::string(lpText) + "\n[This message was intercepted by an IAT hook]";
    std::string newCaption = "[IAT HOOKED] " + std::string(lpCaption);

    // Call the original function with our modified parameters
    int result = g_OriginalMessageBoxA(hWnd, newText.c_str(), newCaption.c_str(), uType);

    std::cout << "[-] MessageBoxA call completed with result: " << result << std::endl;

    return result;
}

/**
 * @brief Structure to represent a module's IAT entry
 */
struct IATEntry
{
    HMODULE module;
    std::string moduleName;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    std::vector<std::pair<std::string, FARPROC *>> functions;
};

/**
 * @brief Finds all IAT entries for a specific module and function
 *
 * @param targetModule Name of the module containing the function to hook
 * @param targetFunction Name of the function to hook
 * @return std::vector<IATEntry> List of IAT entries found
 */
std::vector<IATEntry> FindIATEntries(const std::string &targetModule, const std::string &targetFunction)
{
    std::vector<IATEntry> entries;

    // Get the base address of the current process
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule)
    {
        std::cerr << "Failed to get module handle: " << GetLastError() << std::endl;
        return entries;
    }

    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Invalid DOS header" << std::endl;
        return entries;
    }

    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Invalid NT headers" << std::endl;
        return entries;
    }

    // Get the import directory
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0)
    {
        std::cerr << "No import directory" << std::endl;
        return entries;
    }

    // Get the first import descriptor
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hModule + importDir->VirtualAddress);

    // Iterate through all import descriptors
    for (; importDesc->Name != 0; importDesc++)
    {
        // Get the name of the imported DLL
        char *dllName = (char *)((BYTE *)hModule + importDesc->Name);

        // Check if this is the DLL we're looking for
        if (_stricmp(dllName, targetModule.c_str()) == 0)
        {
            IATEntry entry;
            entry.module = hModule;
            entry.moduleName = dllName;
            entry.importDesc = importDesc;

            // Get the IAT (Import Address Table)
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->FirstThunk);

            // Get the original thunk for function names
            PIMAGE_THUNK_DATA origThunk = NULL;
            if (importDesc->OriginalFirstThunk != 0)
            {
                origThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->OriginalFirstThunk);
            }

            // Iterate through all functions in this import descriptor
            for (int i = 0; thunk[i].u1.Function != 0; i++)
            {
                // Get the function name if available
                std::string functionName = "Unknown";
                if (origThunk && !(origThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)hModule + origThunk[i].u1.AddressOfData);
                    functionName = (char *)importByName->Name;
                }

                // Check if this is the function we're looking for
                if (functionName == targetFunction)
                {
                    // Store the function address pointer for later modification
                    entry.functions.push_back(std::make_pair(functionName, (FARPROC *)&thunk[i].u1.Function));
                }
            }

            if (!entry.functions.empty())
            {
                entries.push_back(entry);
            }
        }
    }

    return entries;
}

/**
 * @brief Installs IAT hooks for a specific function
 *
 * @param targetModule Name of the module containing the function to hook
 * @param targetFunction Name of the function to hook
 * @param hookFunction Pointer to the hook function
 * @param originalFunction Pointer to store the original function address
 * @return true if hook was successfully installed, false otherwise
 */
bool InstallIATHook(const std::string &targetModule, const std::string &targetFunction,
                    FARPROC hookFunction, FARPROC *originalFunction)
{
    // Find all IAT entries for the target function
    std::vector<IATEntry> entries = FindIATEntries(targetModule, targetFunction);

    if (entries.empty())
    {
        std::cerr << "No IAT entries found for " << targetModule << ":" << targetFunction << std::endl;
        return false;
    }

    std::cout << "[+] Found " << entries.size() << " IAT entries for " << targetModule << ":" << targetFunction << std::endl;

    // For each entry, modify the IAT to point to our hook function
    for (const auto &entry : entries)
    {
        for (const auto &func : entry.functions)
        {
            std::cout << "[+] Found function: " << func.first << " at address: " << *func.second << std::endl;

            // Save the original function address
            *originalFunction = *func.second;

            // Change memory protection to allow writing to the IAT
            DWORD oldProtect;
            if (!VirtualProtect(func.second, sizeof(FARPROC), PAGE_READWRITE, &oldProtect))
            {
                std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
                continue;
            }

            // Replace the function address with our hook function
            *func.second = hookFunction;

            // Restore memory protection
            VirtualProtect(func.second, sizeof(FARPROC), oldProtect, &oldProtect);

            std::cout << "[+] Hooked function: " << func.first << " to address: " << hookFunction << std::endl;
        }
    }

    return true;
}

/**
 * @brief Demonstrates the IAT hooking technique
 */
int main()
{
    std::cout << "=== Import Address Table (IAT) Hooking Demonstration ===" << std::endl;
    std::cout << "This program will hook the MessageBoxA function via the IAT" << std::endl;
    std::cout << std::endl;

    // Show a message box before hooking
    std::cout << "[+] Calling MessageBoxA before hooking..." << std::endl;
    MessageBoxA(NULL, "This is the original message", "Original", MB_OK);

    // Install the IAT hook
    std::cout << "[+] Installing IAT hook..." << std::endl;
    if (!InstallIATHook("user32.dll", "MessageBoxA", (FARPROC)HookedMessageBoxA, (FARPROC *)&g_OriginalMessageBoxA))
    {
        std::cerr << "Failed to install IAT hook" << std::endl;
        return 1;
    }

    // Show a message box after hooking
    std::cout << "[+] Calling MessageBoxA after hooking..." << std::endl;
    MessageBoxA(NULL, "This is a test message", "Test", MB_OK);

    std::cout << "[+] Demonstration completed successfully" << std::endl;

    return 0;
}
