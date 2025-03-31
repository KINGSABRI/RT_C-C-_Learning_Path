/**
 * api_hooking.cpp
 * API Hooking and Unhooking Techniques
 *
 * This module demonstrates various API hooking and unhooking techniques
 * that can be used to evade detection by AV/EDR solutions.
 */

#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>

/**
 * This file is for EDUCATIONAL PURPOSES ONLY.
 *
 * SECURITY WARNING: The techniques demonstrated in this code are meant for
 * understanding how AV/EDR evasion works and should only be used in authorized
 * testing environments.
 */

// Forward declarations
void explainAPIHooking();
void explainInlineHooking();
void explainIATHooking();
void explainEATHooking();
void explainVTableHooking();
void explainAPIUnhooking();
void explainDirectSyscalls();

// Dummy function for demonstration purposes
typedef HANDLE(WINAPI *pCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

// Dummy hook function
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // This is just a dummy implementation for demonstration
    std::cout << "HookedCreateFileA called with file: " << lpFileName << std::endl;

    // Call the original function (in a real hook)
    // return OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
    //                           lpSecurityAttributes, dwCreationDisposition,
    //                           dwFlagsAndAttributes, hTemplateFile);

    return INVALID_HANDLE_VALUE; // Dummy return
}

int main()
{
    std::cout << "===== API Hooking and Unhooking Techniques =====" << std::endl;
    std::cout << "This module explains various API hooking and unhooking techniques" << std::endl;
    std::cout << "used for AV/EDR evasion." << std::endl;
    std::cout << std::endl;

    std::cout << "IMPORTANT: This is for educational purposes only. The code is intentionally" << std::endl;
    std::cout << "non-functional to prevent misuse. Real implementation details are omitted." << std::endl;
    std::cout << std::endl;

    explainAPIHooking();

    int choice = 0;
    while (choice != 7)
    {
        std::cout << "\nSelect a topic to learn about:" << std::endl;
        std::cout << "1. Inline Hooking" << std::endl;
        std::cout << "2. IAT Hooking" << std::endl;
        std::cout << "3. EAT Hooking" << std::endl;
        std::cout << "4. VTable Hooking" << std::endl;
        std::cout << "5. API Unhooking" << std::endl;
        std::cout << "6. Direct Syscalls" << std::endl;
        std::cout << "7. Exit" << std::endl;
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            explainInlineHooking();
            break;
        case 2:
            explainIATHooking();
            break;
        case 3:
            explainEATHooking();
            break;
        case 4:
            explainVTableHooking();
            break;
        case 5:
            explainAPIUnhooking();
            break;
        case 6:
            explainDirectSyscalls();
            break;
        case 7:
            std::cout << "Exiting program." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    return 0;
}

/**
 * Explains the concept of API hooking and its relevance to AV/EDR evasion
 */
void explainAPIHooking()
{
    std::cout << "----- API Hooking Overview -----" << std::endl;
    std::cout << "API hooking is a technique used to intercept calls to API functions." << std::endl;
    std::cout << "It allows monitoring, modifying, or redirecting the execution flow of API calls." << std::endl;
    std::cout << std::endl;

    std::cout << "In the context of security:" << std::endl;
    std::cout << "- AV/EDR solutions often use API hooking to monitor for suspicious behavior" << std::endl;
    std::cout << "- Malware may use API hooking to intercept sensitive information" << std::endl;
    std::cout << "- Security tools may use API unhooking to bypass AV/EDR monitoring" << std::endl;
    std::cout << std::endl;

    std::cout << "Common API hooking targets for AV/EDR:" << std::endl;
    std::cout << "- Process creation: CreateProcess, NtCreateProcess" << std::endl;
    std::cout << "- Memory operations: VirtualAlloc, VirtualProtect, WriteProcessMemory" << std::endl;
    std::cout << "- Thread operations: CreateThread, CreateRemoteThread" << std::endl;
    std::cout << "- File operations: CreateFile, WriteFile" << std::endl;
    std::cout << "- Registry operations: RegOpenKey, RegSetValue" << std::endl;
    std::cout << "- Network operations: socket, connect, send" << std::endl;
    std::cout << std::endl;

    std::cout << "API hooking methods:" << std::endl;
    std::cout << "1. Inline hooking: Modifying the function's code at runtime" << std::endl;
    std::cout << "2. IAT hooking: Modifying the Import Address Table" << std::endl;
    std::cout << "3. EAT hooking: Modifying the Export Address Table" << std::endl;
    std::cout << "4. VTable hooking: Modifying virtual function tables" << std::endl;
    std::cout << std::endl;

    std::cout << "API unhooking methods:" << std::endl;
    std::cout << "1. Restoring original bytes: Reverting modifications made by hooks" << std::endl;
    std::cout << "2. Module reloading: Loading a fresh copy of the DLL" << std::endl;
    std::cout << "3. Direct syscalls: Bypassing the API layer entirely" << std::endl;
}

/**
 * Explains inline hooking techniques
 */
void explainInlineHooking()
{
    std::cout << "\n----- Inline Hooking -----" << std::endl;
    std::cout << "Inline hooking involves modifying the first few bytes of a function's code" << std::endl;
    std::cout << "to redirect execution to a hook function. It's one of the most common" << std::endl;
    std::cout << "hooking techniques used by both AV/EDR solutions and malware." << std::endl;
    std::cout << std::endl;

    std::cout << "Basic steps:" << std::endl;
    std::cout << "1. Locate the target function in memory" << std::endl;
    std::cout << "2. Save the original bytes (for later restoration)" << std::endl;
    std::cout << "3. Write a jump instruction to redirect to the hook function" << std::endl;
    std::cout << "4. In the hook function, execute custom code" << std::endl;
    std::cout << "5. Optionally, call the original function by executing the saved bytes" << std::endl;
    std::cout << "   and jumping back to the original function after the hook" << std::endl;
    std::cout << std::endl;

    std::cout << "Example (x86):" << std::endl;
    std::cout << "// Original function beginning (CreateFileA)\n"
              << "8B FF                 mov edi, edi\n"
              << "55                    push ebp\n"
              << "8B EC                 mov ebp, esp\n"
              << "...\n\n"
              << "// After hooking\n"
              << "E9 XX XX XX XX       jmp HookedCreateFileA  // Jump to our hook\n"
              << "...\n";
    std::cout << std::endl;

    std::cout << "Pseudocode for setting up an inline hook:" << std::endl;
    std::cout << "// Get the address of the target function\n"
              << "FARPROC pCreateFileA = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"CreateFileA\");\n\n"
              << "// Save the original bytes\n"
              << "BYTE originalBytes[5];\n"
              << "memcpy(originalBytes, pCreateFileA, 5);\n\n"
              << "// Make the memory writable\n"
              << "DWORD oldProtect;\n"
              << "VirtualProtect(pCreateFileA, 5, PAGE_EXECUTE_READWRITE, &oldProtect);\n\n"
              << "// Write the jump instruction\n"
              << "BYTE jumpBytes[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };\n"
              << "// Calculate the relative address for the jump\n"
              << "*(DWORD*)&jumpBytes[1] = (DWORD)HookedCreateFileA - (DWORD)pCreateFileA - 5;\n"
              << "memcpy(pCreateFileA, jumpBytes, 5);\n\n"
              << "// Restore the original protection\n"
              << "VirtualProtect(pCreateFileA, 5, oldProtect, &oldProtect);\n";
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Scanning for unexpected jump instructions at the beginning of API functions" << std::endl;
    std::cout << "- Comparing the in-memory code with the on-disk code" << std::endl;
    std::cout << "- Checking for memory regions with changed protection" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Hooking less commonly monitored functions" << std::endl;
    std::cout << "- Using more sophisticated hooking methods" << std::endl;
    std::cout << "- Implementing hooks that are difficult to distinguish from legitimate code" << std::endl;
}

/**
 * Explains IAT hooking techniques
 */
void explainIATHooking()
{
    std::cout << "\n----- IAT Hooking -----" << std::endl;
    std::cout << "IAT (Import Address Table) hooking involves modifying the addresses in a" << std::endl;
    std::cout << "process's IAT to redirect API calls to hook functions. The IAT contains" << std::endl;
    std::cout << "pointers to all imported functions used by a module." << std::endl;
    std::cout << std::endl;

    std::cout << "Basic steps:" << std::endl;
    std::cout << "1. Locate the IAT entry for the target function" << std::endl;
    std::cout << "2. Save the original address" << std::endl;
    std::cout << "3. Replace the address with the address of the hook function" << std::endl;
    std::cout << "4. In the hook function, execute custom code" << std::endl;
    std::cout << "5. Optionally, call the original function using the saved address" << std::endl;
    std::cout << std::endl;

    std::cout << "Pseudocode for setting up an IAT hook:" << std::endl;
    std::cout << "// Get the base address of the module to hook\n"
              << "HMODULE hModule = GetModuleHandle(NULL); // Current process\n\n"
              << "// Get the DOS header\n"
              << "PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;\n\n"
              << "// Get the NT headers\n"
              << "PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);\n\n"
              << "// Get the import descriptor\n"
              << "PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +\n"
              << "    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);\n\n"
              << "// Iterate through the import descriptors\n"
              << "while (importDesc->Name) {\n"
              << "    // Get the name of the imported DLL\n"
              << "    char* dllName = (char*)((BYTE*)hModule + importDesc->Name);\n"
              << "    \n"
              << "    // Check if this is the DLL we're interested in\n"
              << "    if (strcmp(dllName, \"KERNEL32.dll\") == 0) {\n"
              << "        // Get the IAT\n"
              << "        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);\n"
              << "        \n"
              << "        // Iterate through the IAT\n"
              << "        while (thunk->u1.Function) {\n"
              << "            // Get the address of the imported function\n"
              << "            FARPROC* funcAddr = (FARPROC*)&thunk->u1.Function;\n"
              << "            \n"
              << "            // Check if this is the function we want to hook\n"
              << "            if (*funcAddr == GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"CreateFileA\")) {\n"
              << "                // Save the original address\n"
              << "                OriginalCreateFileA = (pCreateFileA)*funcAddr;\n"
              << "                \n"
              << "                // Make the IAT writable\n"
              << "                DWORD oldProtect;\n"
              << "                VirtualProtect(funcAddr, sizeof(FARPROC), PAGE_READWRITE, &oldProtect);\n"
              << "                \n"
              << "                // Replace the address with our hook\n"
              << "                *funcAddr = (FARPROC)HookedCreateFileA;\n"
              << "                \n"
              << "                // Restore the protection\n"
              << "                VirtualProtect(funcAddr, sizeof(FARPROC), oldProtect, &oldProtect);\n"
              << "                \n"
              << "                break;\n"
              << "            }\n"
              << "            \n"
              << "            thunk++;\n"
              << "        }\n"
              << "    }\n"
              << "    \n"
              << "    importDesc++;\n"
              << "}\n";
    std::cout << std::endl;

    std::cout << "Advantages of IAT hooking:" << std::endl;
    std::cout << "- Doesn't modify the code of the target function" << std::endl;
    std::cout << "- Affects only the current process" << std::endl;
    std::cout << "- Relatively simple to implement" << std::endl;
    std::cout << std::endl;

    std::cout << "Limitations:" << std::endl;
    std::cout << "- Only works for functions imported via the IAT" << std::endl;
    std::cout << "- Doesn't affect functions resolved dynamically with GetProcAddress" << std::endl;
    std::cout << "- Easily detected by comparing IAT entries with the actual function addresses" << std::endl;
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Scanning for modified IAT entries" << std::endl;
    std::cout << "- Comparing IAT addresses with the actual function addresses" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Hooking less commonly monitored functions" << std::endl;
    std::cout << "- Temporarily unhooking when sensitive operations are performed" << std::endl;
    std::cout << "- Combining with other hooking methods" << std::endl;
}

/**
 * Explains EAT hooking techniques
 */
void explainEATHooking()
{
    std::cout << "\n----- EAT Hooking -----" << std::endl;
    std::cout << "EAT (Export Address Table) hooking involves modifying the addresses in a" << std::endl;
    std::cout << "DLL's export table to redirect calls to exported functions. This affects" << std::endl;
    std::cout << "all processes that use the hooked DLL." << std::endl;
    std::cout << std::endl;

    std::cout << "Basic steps:" << std::endl;
    std::cout << "1. Locate the EAT entry for the target function" << std::endl;
    std::cout << "2. Save the original address" << std::endl;
    std::cout << "3. Replace the address with the address of the hook function" << std::endl;
    std::cout << "4. In the hook function, execute custom code" << std::endl;
    std::cout << "5. Optionally, call the original function using the saved address" << std::endl;
    std::cout << std::endl;

    std::cout << "Pseudocode for setting up an EAT hook:" << std::endl;
    std::cout << "// Get the base address of the DLL to hook\n"
              << "HMODULE hModule = GetModuleHandle(\"kernel32.dll\");\n\n"
              << "// Get the DOS header\n"
              << "PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;\n\n"
              << "// Get the NT headers\n"
              << "PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);\n\n"
              << "// Get the export directory\n"
              << "PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +\n"
              << "    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n\n"
              << "// Get the arrays of function names, ordinals, and addresses\n"
              << "DWORD* nameArray = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);\n"
              << "WORD* ordinalArray = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);\n"
              << "DWORD* addressArray = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);\n\n"
              << "// Find the target function\n"
              << "for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {\n"
              << "    char* funcName = (char*)((BYTE*)hModule + nameArray[i]);\n"
              << "    \n"
              << "    if (strcmp(funcName, \"CreateFileA\") == 0) {\n"
              << "        // Get the function's ordinal\n"
              << "        WORD ordinal = ordinalArray[i];\n"
              << "        \n"
              << "        // Save the original address\n"
              << "        OriginalCreateFileA = (pCreateFileA)((BYTE*)hModule + addressArray[ordinal]);\n"
              << "        \n"
              << "        // Make the address array writable\n"
              << "        DWORD oldProtect;\n"
              << "        VirtualProtect(&addressArray[ordinal], sizeof(DWORD), PAGE_READWRITE, &oldProtect);\n"
              << "        \n"
              << "        // Replace the address with our hook\n"
              << "        addressArray[ordinal] = (DWORD)HookedCreateFileA - (DWORD)hModule;\n"
              << "        \n"
              << "        // Restore the protection\n"
              << "        VirtualProtect(&addressArray[ordinal], sizeof(DWORD), oldProtect, &oldProtect);\n"
              << "        \n"
              << "        break;\n"
              << "    }\n"
              << "}\n";
    std::cout << std::endl;

    std::cout << "Advantages of EAT hooking:" << std::endl;
    std::cout << "- Affects all processes that use the hooked DLL" << std::endl;
    std::cout << "- Can intercept functions even when they're resolved with GetProcAddress" << std::endl;
    std::cout << std::endl;

    std::cout << "Limitations:" << std::endl;
    std::cout << "- Requires administrator privileges to modify system DLLs" << std::endl;
    std::cout << "- More complex to implement than IAT hooking" << std::endl;
    std::cout << "- Easily detected by comparing EAT entries with the actual function addresses" << std::endl;
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Scanning for modified EAT entries" << std::endl;
    std::cout << "- Comparing EAT addresses with the actual function addresses" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Hooking less commonly monitored functions" << std::endl;
    std::cout << "- Temporarily unhooking when sensitive operations are performed" << std::endl;
    std::cout << "- Combining with other hooking methods" << std::endl;
}

/**
 * Explains VTable hooking techniques
 */
void explainVTableHooking()
{
    std::cout << "\n----- VTable Hooking -----" << std::endl;
    std::cout << "VTable (Virtual Function Table) hooking involves modifying the virtual" << std::endl;
    std::cout << "function tables of C++ objects to redirect calls to virtual methods." << std::endl;
    std::cout << "This technique is commonly used to hook COM objects and C++ classes." << std::endl;
    std::cout << std::endl;

    std::cout << "Basic steps:" << std::endl;
    std::cout << "1. Locate the VTable of the target object" << std::endl;
    std::cout << "2. Save the original function pointer" << std::endl;
    std::cout << "3. Replace the function pointer with the address of the hook function" << std::endl;
    std::cout << "4. In the hook function, execute custom code" << std::endl;
    std::cout << "5. Optionally, call the original function using the saved pointer" << std::endl;
    std::cout << std::endl;

    std::cout << "Example of a C++ class with a VTable:" << std::endl;
    std::cout << "class BaseClass {\n"
              << "public:\n"
              << "    virtual void Method1() { /* ... */ }\n"
              << "    virtual void Method2() { /* ... */ }\n"
              << "};\n\n"
              << "// Memory layout of an object of BaseClass:\n"
              << "// [VTable pointer] -> [VTable] -> [Method1 pointer]\n"
              << "//                               -> [Method2 pointer]\n";
    std::cout << std::endl;

    std::cout << "Pseudocode for setting up a VTable hook:" << std::endl;
    std::cout << "// Get the VTable pointer from the object\n"
              << "BaseClass* obj = new BaseClass();\n"
              << "void** vTable = *(void***)obj;\n\n"
              << "// Save the original method pointer (Method1)\n"
              << "void* originalMethod = vTable[0];\n\n"
              << "// Make the VTable writable\n"
              << "DWORD oldProtect;\n"
              << "VirtualProtect(&vTable[0], sizeof(void*), PAGE_READWRITE, &oldProtect);\n\n"
              << "// Replace the method pointer with our hook\n"
              << "vTable[0] = HookedMethod1;\n\n"
              << "// Restore the protection\n"
              << "VirtualProtect(&vTable[0], sizeof(void*), oldProtect, &oldProtect);\n";
    std::cout << std::endl;

    std::cout << "Advantages of VTable hooking:" << std::endl;
    std::cout << "- Can hook C++ virtual methods and COM interfaces" << std::endl;
    std::cout << "- Less commonly monitored than API hooking" << std::endl;
    std::cout << "- Can be used to hook high-level abstractions" << std::endl;
    std::cout << std::endl;

    std::cout << "Limitations:" << std::endl;
    std::cout << "- Only works for virtual methods" << std::endl;
    std::cout << "- Requires knowledge of the class structure" << std::endl;
    std::cout << "- May be affected by compiler optimizations" << std::endl;
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Scanning for modified VTables" << std::endl;
    std::cout << "- Checking the integrity of COM objects" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Hooking less commonly used interfaces" << std::endl;
    std::cout << "- Temporarily unhooking when sensitive operations are performed" << std::endl;
    std::cout << "- Implementing hooks that are difficult to distinguish from legitimate code" << std::endl;
}

/**
 * Explains API unhooking techniques
 */
void explainAPIUnhooking()
{
    std::cout << "\n----- API Unhooking -----" << std::endl;
    std::cout << "API unhooking involves removing or bypassing hooks placed by AV/EDR solutions" << std::endl;
    std::cout << "to monitor API calls. This technique is used to evade detection by preventing" << std::endl;
    std::cout << "security products from monitoring malicious activities." << std::endl;
    std::cout << std::endl;

    std::cout << "Common unhooking methods:" << std::endl;
    std::cout << "1. Restoring original bytes: Reverting modifications made by inline hooks" << std::endl;
    std::cout << "2. Module reloading: Loading a fresh copy of the DLL" << std::endl;
    std::cout << "3. Direct syscalls: Bypassing the API layer entirely" << std::endl;
    std::cout << std::endl;

    std::cout << "Method 1: Restoring original bytes" << std::endl;
    std::cout << "Pseudocode:" << std::endl;
    std::cout << "// Get the address of the hooked function\n"
              << "FARPROC pNtCreateFile = GetProcAddress(GetModuleHandle(\"ntdll.dll\"), \"NtCreateFile\");\n\n"
              << "// Check if it's hooked (e.g., by looking for a jump instruction)\n"
              << "if (*(BYTE*)pNtCreateFile == 0xE9) { // JMP instruction\n"
              << "    // It's hooked, so restore the original bytes\n"
              << "    \n"
              << "    // Option 1: If we know the original bytes\n"
              << "    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, ... }; // Example bytes\n"
              << "    \n"
              << "    // Make the memory writable\n"
              << "    DWORD oldProtect;\n"
              << "    VirtualProtect(pNtCreateFile, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);\n"
              << "    \n"
              << "    // Restore the original bytes\n"
              << "    memcpy(pNtCreateFile, originalBytes, sizeof(originalBytes));\n"
              << "    \n"
              << "    // Restore the protection\n"
              << "    VirtualProtect(pNtCreateFile, sizeof(originalBytes), oldProtect, &oldProtect);\n"
              << "}\n";
    std::cout << std::endl;

    std::cout << "Method 2: Module reloading" << std::endl;
    std::cout << "Pseudocode:" << std::endl;
    std::cout << "// Map a fresh copy of ntdll.dll into memory\n"
              << "HANDLE hFile = CreateFile(\"C:\\\\Windows\\\\System32\\\\ntdll.dll\", GENERIC_READ,\n"
              << "                         FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);\n\n"
              << "// Create a file mapping\n"
              << "HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);\n\n"
              << "// Map the file into memory\n"
              << "LPVOID mappedDll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);\n\n"
              << "// Now we have a fresh, unhooked copy of ntdll.dll\n"
              << "// We can use it to find the original, unhooked functions\n\n"
              << "// Find the export directory\n"
              << "// ... (similar to EAT hooking code)\n\n"
              << "// Find the NtCreateFile function in the mapped DLL\n"
              << "// Use it instead of the hooked version\n";
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Monitoring for modifications to hooked functions" << std::endl;
    std::cout << "- Detecting unusual DLL loading patterns" << std::endl;
    std::cout << "- Monitoring for direct syscall patterns" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Implementing stealthy unhooking methods" << std::endl;
    std::cout << "- Unhooking only when necessary" << std::endl;
    std::cout << "- Combining multiple unhooking methods" << std::endl;
}

/**
 * Explains direct syscall techniques
 */
void explainDirectSyscalls()
{
    std::cout << "\n----- Direct Syscalls -----" << std::endl;
    std::cout << "Direct syscalls involve bypassing the Windows API layer entirely and making" << std::endl;
    std::cout << "syscalls directly to the kernel. This technique avoids hooks placed at the" << std::endl;
    std::cout << "API level by AV/EDR solutions." << std::endl;
    std::cout << std::endl;

    std::cout << "Basic concept:" << std::endl;
    std::cout << "- Windows API functions (e.g., CreateFile) eventually call into ntdll.dll" << std::endl;
    std::cout << "- ntdll.dll functions (e.g., NtCreateFile) make syscalls to the kernel" << std::endl;
    std::cout << "- By directly making the syscalls, we bypass any hooks in the API layer" << std::endl;
    std::cout << std::endl;

    std::cout << "Implementation approaches:" << std::endl;
    std::cout << "1. Manually implementing syscall instructions" << std::endl;
    std::cout << "2. Extracting syscall numbers from ntdll.dll" << std::endl;
    std::cout << "3. Using syscall stubs from a fresh copy of ntdll.dll" << std::endl;
    std::cout << std::endl;

    std::cout << "Example of a direct syscall (x64):" << std::endl;
    std::cout << "// Define the syscall function\n"
              << "extern \"C\" NTSTATUS NtCreateFile_Syscall(\n"
              << "    PHANDLE FileHandle,\n"
              << "    ACCESS_MASK DesiredAccess,\n"
              << "    POBJECT_ATTRIBUTES ObjectAttributes,\n"
              << "    PIO_STATUS_BLOCK IoStatusBlock,\n"
              << "    PLARGE_INTEGER AllocationSize,\n"
              << "    ULONG FileAttributes,\n"
              << "    ULONG ShareAccess,\n"
              << "    ULONG CreateDisposition,\n"
              << "    ULONG CreateOptions,\n"
              << "    PVOID EaBuffer,\n"
              << "    ULONG EaLength);\n\n"
              << "// Assembly implementation (x64)\n"
              << "__asm {\n"
              << "NtCreateFile_Syscall:\n"
              << "    mov r10, rcx          ; Save first parameter\n"
              << "    mov eax, 0x55         ; Syscall number for NtCreateFile\n"
              << "    syscall               ; Make the syscall\n"
              << "    ret                   ; Return to caller\n"
              << "}\n";
    std::cout << std::endl;

    std::cout << "Challenges:" << std::endl;
    std::cout << "- Syscall numbers change between Windows versions" << std::endl;
    std::cout << "- Complex structures and parameters must be set up correctly" << std::endl;
    std::cout << "- Error handling is more difficult" << std::endl;
    std::cout << "- Some AV/EDR solutions now monitor for direct syscalls" << std::endl;
    std::cout << std::endl;

    std::cout << "Detection methods:" << std::endl;
    std::cout << "- Monitoring for syscall instructions outside of ntdll.dll" << std::endl;
    std::cout << "- Detecting unusual patterns of syscalls" << std::endl;
    std::cout << "- Kernel-level monitoring of syscalls" << std::endl;
    std::cout << std::endl;

    std::cout << "Evasion techniques:" << std::endl;
    std::cout << "- Dynamically resolving syscall numbers at runtime" << std::endl;
    std::cout << "- Implementing syscalls in a way that mimics legitimate code" << std::endl;
    std::cout << "- Using indirect syscalls (calling into unhooked parts of ntdll.dll)" << std::endl;
}
