/**
 * @file detour_hooking.cpp
 * @brief Demonstrates function detour hooking techniques on Windows
 *
 * This file demonstrates how to implement function detours, which is a more
 * sophisticated hooking technique that preserves the original function prologue
 * and creates a trampoline to execute the original code. This approach is more
 * robust than simple inline hooking.
 *
 * WARNING: This code is for educational purposes only. Hooking system APIs
 * can destabilize the system and should only be done in controlled environments.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 detour_hooking.cpp -o detour_hooking.exe
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

// Original function address
MessageBoxAType g_OriginalMessageBoxA = nullptr;

// Trampoline function - will be dynamically created
MessageBoxAType g_TrampolineFunction = nullptr;

// Size of the trampoline code
const size_t TRAMPOLINE_SIZE = 64;

/**
 * @brief Our hook function that will replace MessageBoxA
 *
 * This function will be called instead of the original MessageBoxA.
 * It modifies the behavior by changing the message text and then
 * calls the original function via the trampoline.
 */
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // Print information about the intercepted call
    std::cout << "[-] MessageBoxA hooked via detour!" << std::endl;
    std::cout << "[-] Original text: " << lpText << std::endl;
    std::cout << "[-] Original caption: " << lpCaption << std::endl;

    // Modify the parameters
    std::string newText = std::string(lpText) + "\n[This message was intercepted by a detour hook]";
    std::string newCaption = "[DETOUR HOOKED] " + std::string(lpCaption);

    // Call the original function via the trampoline with our modified parameters
    int result = g_TrampolineFunction(hWnd, newText.c_str(), newCaption.c_str(), uType);

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
 * @brief Determines the minimum size of instructions to copy for a safe detour
 *
 * This is a simplified implementation. In a real-world scenario, you would need
 * a proper disassembler to analyze the instructions and ensure you're not breaking
 * any instruction in the middle.
 *
 * @param address Address of the function to analyze
 * @return size_t Minimum size in bytes to copy (at least 5 for the JMP instruction)
 */
size_t GetInstructionSize(void *address)
{
    // This is a simplified implementation
    // In a real-world scenario, you would use a disassembler library

    // For demonstration purposes, we'll assume the first 5 bytes are safe to replace
    // In a real implementation, you would analyze the instructions to ensure
    // you're not breaking any instruction in the middle

    return 5;
}

/**
 * @brief Creates a trampoline function that executes the original code
 *
 * The trampoline function contains:
 * 1. The original instructions that were overwritten by our hook
 * 2. A JMP instruction to the rest of the original function
 *
 * @param originalFunction Address of the original function
 * @param hookFunction Address of our hook function
 * @param trampolineSize Size of the trampoline buffer
 * @return void* Address of the created trampoline function
 */
void *CreateTrampoline(void *originalFunction, void *hookFunction, size_t trampolineSize)
{
    // Determine how many bytes we need to copy from the original function
    size_t bytesToCopy = GetInstructionSize(originalFunction);

    // Ensure we have enough space for the trampoline
    if (bytesToCopy + 5 > trampolineSize)
    {
        std::cerr << "Trampoline buffer too small" << std::endl;
        return nullptr;
    }

    // Allocate memory for the trampoline function
    void *trampolineBuffer = VirtualAlloc(NULL, trampolineSize,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!trampolineBuffer)
    {
        std::cerr << "Failed to allocate trampoline buffer: " << GetLastError() << std::endl;
        return nullptr;
    }

    // Copy the original instructions to the trampoline
    memcpy(trampolineBuffer, originalFunction, bytesToCopy);

    // Calculate the address to jump to after the copied instructions
    BYTE *jumpAddress = (BYTE *)originalFunction + bytesToCopy;

    // Add a JMP instruction to the rest of the original function
    BYTE *trampolineJmp = (BYTE *)trampolineBuffer + bytesToCopy;
    trampolineJmp[0] = 0xE9; // JMP opcode

    // Calculate the relative address for the JMP instruction
    DWORD jmpOffset = (DWORD)((BYTE *)jumpAddress - (BYTE *)trampolineJmp - 5);
    memcpy(trampolineJmp + 1, &jmpOffset, sizeof(jmpOffset));

    std::cout << "[+] Created trampoline at " << trampolineBuffer << std::endl;
    std::cout << "[+] Original bytes copied: ";
    PrintMemory(trampolineBuffer, bytesToCopy);
    std::cout << "[+] Jump to: " << jumpAddress << std::endl;

    return trampolineBuffer;
}

/**
 * @brief Installs a detour hook
 *
 * @param targetFunction Name of the function to hook
 * @param hookFunction Pointer to the hook function
 * @param originalFunction Pointer to store the original function address
 * @return true if hook was successfully installed, false otherwise
 */
bool InstallDetourHook(const char *targetFunction, void *hookFunction, void **originalFunction)
{
    // Get the address of the function we want to hook
    HMODULE hModule = GetModuleHandleA("user32.dll");
    if (!hModule)
    {
        std::cerr << "Failed to get module handle: " << GetLastError() << std::endl;
        return false;
    }

    *originalFunction = GetProcAddress(hModule, targetFunction);
    if (!*originalFunction)
    {
        std::cerr << "Failed to get function address: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "[+] Original " << targetFunction << " address: " << *originalFunction << std::endl;

    // Create a trampoline function
    g_TrampolineFunction = (MessageBoxAType)CreateTrampoline(*originalFunction, hookFunction, TRAMPOLINE_SIZE);
    if (!g_TrampolineFunction)
    {
        std::cerr << "Failed to create trampoline" << std::endl;
        return false;
    }

    // Print the original function bytes
    std::cout << "[+] Original function bytes: ";
    PrintMemory(*originalFunction, 5);

    // Calculate the relative address for the JMP instruction
    // JMP instruction uses relative addressing: target = current + 5 + offset
    // So offset = target - current - 5
    DWORD offset = (DWORD)((BYTE *)hookFunction - (BYTE *)*originalFunction - 5);

    // Prepare the JMP instruction (E9 = JMP opcode, followed by 4-byte offset)
    BYTE patch[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    memcpy(patch + 1, &offset, sizeof(offset));

    std::cout << "[+] Hook patch bytes: ";
    PrintMemory(patch, 5);

    // Change memory protection to allow writing to code
    DWORD oldProtect;
    if (!VirtualProtect(*originalFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
        return false;
    }

    // Write the JMP instruction to the beginning of the original function
    memcpy(*originalFunction, patch, 5);

    // Restore original memory protection
    VirtualProtect(*originalFunction, 5, oldProtect, &oldProtect);

    std::cout << "[+] Hook installed successfully" << std::endl;
    std::cout << "[+] Modified bytes: ";
    PrintMemory(*originalFunction, 5);

    return true;
}

/**
 * @brief Demonstrates the detour hooking technique
 */
int main()
{
    std::cout << "=== Function Detour Hooking Demonstration ===" << std::endl;
    std::cout << "This program will hook the MessageBoxA function using a detour" << std::endl;
    std::cout << std::endl;

    // Show a message box before hooking
    std::cout << "[+] Calling MessageBoxA before hooking..." << std::endl;
    MessageBoxA(NULL, "This is the original message", "Original", MB_OK);

    // Install the detour hook
    std::cout << "[+] Installing detour hook..." << std::endl;
    if (!InstallDetourHook("MessageBoxA", (void *)HookedMessageBoxA, (void **)&g_OriginalMessageBoxA))
    {
        std::cerr << "Failed to install detour hook" << std::endl;
        return 1;
    }

    // Show a message box after hooking
    std::cout << "[+] Calling MessageBoxA after hooking..." << std::endl;
    MessageBoxA(NULL, "This is a test message", "Test", MB_OK);

    std::cout << "[+] Demonstration completed successfully" << std::endl;

    // Clean up
    if (g_TrampolineFunction)
    {
        VirtualFree(g_TrampolineFunction, 0, MEM_RELEASE);
    }

    return 0;
}
