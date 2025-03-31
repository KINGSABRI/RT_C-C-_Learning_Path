/**
 * @file inline_hooking.cpp
 * @brief Demonstrates inline API hooking techniques on Windows
 *
 * This file demonstrates how to implement inline API hooking, which involves
 * modifying the first few bytes of a target function to redirect execution
 * to our hook function. This is a common technique used in security research,
 * malware analysis, and reverse engineering.
 *
 * WARNING: This code is for educational purposes only. Hooking system APIs
 * can destabilize the system and should only be done in controlled environments.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 inline_hooking.cpp -o inline_hooking.exe
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

// Define the prototype of the function we want to hook
typedef int(WINAPI *MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);

// Original function bytes storage
BYTE g_originalBytes[5] = {0};
// Address of the original function
FARPROC g_originalFunction = nullptr;

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
    std::cout << "[-] MessageBoxA hooked!" << std::endl;
    std::cout << "[-] Original text: " << lpText << std::endl;
    std::cout << "[-] Original caption: " << lpCaption << std::endl;

    // Modify the parameters
    std::string newText = std::string(lpText) + "\n[This message was intercepted by a hook]";
    std::string newCaption = "[HOOKED] " + std::string(lpCaption);

    // Temporarily remove our hook to call the original function
    // This is necessary to avoid infinite recursion
    DisableHook();

    // Call the original function with our modified parameters
    MessageBoxAType originalMessageBoxA = (MessageBoxAType)g_originalFunction;
    int result = originalMessageBoxA(hWnd, newText.c_str(), newCaption.c_str(), uType);

    // Re-enable our hook
    EnableHook();

    std::cout << "[-] MessageBoxA call completed with result: " << result << std::endl;

    return result;
}

/**
 * @brief Prints a memory region as hexadecimal bytes
 *
 * @param address Starting address of memory to print
 * @param size Number of bytes to print
 */
void PrintMemory(void *address, size_t size)
{
    BYTE *bytes = (BYTE *)address;

    std::cout << "Memory at " << address << ":" << std::endl;
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes[i]) << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

/**
 * @brief Installs the inline hook
 *
 * This function modifies the first 5 bytes of the target function to
 * implement a JMP instruction to our hook function.
 *
 * @return true if hook was successfully installed, false otherwise
 */
bool EnableHook()
{
    // Get the address of the function we want to hook
    HMODULE hModule = GetModuleHandleA("user32.dll");
    if (!hModule)
    {
        std::cerr << "Failed to get module handle: " << GetLastError() << std::endl;
        return false;
    }

    g_originalFunction = GetProcAddress(hModule, "MessageBoxA");
    if (!g_originalFunction)
    {
        std::cerr << "Failed to get function address: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "[+] Original MessageBoxA address: " << g_originalFunction << std::endl;

    // Save the original bytes for later restoration
    memcpy(g_originalBytes, g_originalFunction, 5);

    std::cout << "[+] Original bytes: ";
    PrintMemory(g_originalFunction, 5);

    // Calculate the relative address for the JMP instruction
    // JMP instruction uses relative addressing: target = current + 5 + offset
    // So offset = target - current - 5
    DWORD offset = (DWORD)((BYTE *)HookedMessageBoxA - (BYTE *)g_originalFunction - 5);

    // Prepare the JMP instruction (E9 = JMP opcode, followed by 4-byte offset)
    BYTE patch[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    memcpy(patch + 1, &offset, sizeof(offset));

    std::cout << "[+] Hook patch bytes: ";
    PrintMemory(patch, 5);

    // Change memory protection to allow writing to code
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)g_originalFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
        return false;
    }

    // Write the JMP instruction to the beginning of the original function
    memcpy((LPVOID)g_originalFunction, patch, 5);

    // Restore original memory protection
    VirtualProtect((LPVOID)g_originalFunction, 5, oldProtect, &oldProtect);

    std::cout << "[+] Hook installed successfully" << std::endl;
    std::cout << "[+] Modified bytes: ";
    PrintMemory(g_originalFunction, 5);

    return true;
}

/**
 * @brief Removes the hook by restoring the original bytes
 *
 * @return true if hook was successfully removed, false otherwise
 */
bool DisableHook()
{
    if (!g_originalFunction)
    {
        std::cerr << "Original function address not set" << std::endl;
        return false;
    }

    // Change memory protection to allow writing to code
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)g_originalFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
        return false;
    }

    // Restore the original bytes
    memcpy((LPVOID)g_originalFunction, g_originalBytes, 5);

    // Restore original memory protection
    VirtualProtect((LPVOID)g_originalFunction, 5, oldProtect, &oldProtect);

    return true;
}

/**
 * @brief Demonstrates the inline hooking technique
 */
int main()
{
    std::cout << "=== Inline API Hooking Demonstration ===" << std::endl;
    std::cout << "This program will hook the MessageBoxA function" << std::endl;
    std::cout << std::endl;

    // Show a message box before hooking
    std::cout << "[+] Calling MessageBoxA before hooking..." << std::endl;
    MessageBoxA(NULL, "This is the original message", "Original", MB_OK);

    // Install the hook
    if (!EnableHook())
    {
        std::cerr << "Failed to install hook" << std::endl;
        return 1;
    }

    // Show a message box after hooking
    std::cout << "[+] Calling MessageBoxA after hooking..." << std::endl;
    MessageBoxA(NULL, "This is a test message", "Test", MB_OK);

    // Remove the hook
    if (!DisableHook())
    {
        std::cerr << "Failed to remove hook" << std::endl;
        return 1;
    }

    std::cout << "[+] Hook removed" << std::endl;

    // Show a message box after removing the hook
    std::cout << "[+] Calling MessageBoxA after removing hook..." << std::endl;
    MessageBoxA(NULL, "This is the original message again", "Original", MB_OK);

    std::cout << "[+] Demonstration completed successfully" << std::endl;

    return 0;
}
