/**
 * @file windows_internals.cpp
 * @brief Demonstrates advanced Windows internals concepts and techniques
 *
 * This file explores advanced Windows internals concepts including the Windows
 * kernel architecture, system calls, process and thread internals, and memory
 * management internals. Understanding these concepts is crucial for advanced
 * exploitation, debugging, and security research.
 *
 * WARNING: Some techniques demonstrated here may require elevated privileges.
 * Only use these techniques on systems you own or have permission to analyze.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 windows_internals.cpp -o windows_internals.exe
 *
 * Red Team Applications:
 * - Developing sophisticated exploits that leverage OS internals
 * - Creating advanced persistence mechanisms
 * - Bypassing security controls through low-level operations
 * - Understanding and evading detection mechanisms
 */

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <psapi.h>
#include <tlhelp32.h>

// Function prototypes
void demonstrate_system_calls();
void demonstrate_process_internals();
void demonstrate_thread_internals();
void demonstrate_memory_internals();
void demonstrate_handle_table();
void print_memory(const void *addr, size_t len);

// Undocumented Windows structures and functions
typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    SYSTEM_HANDLE_INFORMATION Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/**
 * @brief Main function that demonstrates different Windows internals concepts
 */
int main()
{
    std::cout << "=== Advanced Windows Internals Demonstration ===" << std::endl;
    std::cout << std::endl;

    // Demonstrate system calls
    std::cout << "1. System Calls:" << std::endl;
    demonstrate_system_calls();
    std::cout << std::endl;

    // Demonstrate process internals
    std::cout << "2. Process Internals:" << std::endl;
    demonstrate_process_internals();
    std::cout << std::endl;

    // Demonstrate thread internals
    std::cout << "3. Thread Internals:" << std::endl;
    demonstrate_thread_internals();
    std::cout << std::endl;

    // Demonstrate memory internals
    std::cout << "4. Memory Internals:" << std::endl;
    demonstrate_memory_internals();
    std::cout << std::endl;

    // Demonstrate handle table
    std::cout << "5. Handle Table:" << std::endl;
    demonstrate_handle_table();

    return 0;
}

/**
 * @brief Prints a memory region as hexadecimal bytes and ASCII characters
 *
 * @param addr Starting address of memory to print
 * @param len Number of bytes to print
 */
void print_memory(const void *addr, size_t len)
{
    const unsigned char *p = static_cast<const unsigned char *>(addr);

    for (size_t i = 0; i < len; i += 16)
    {
        // Print address
        std::cout << std::setw(8) << std::setfill('0') << std::hex << (uintptr_t)(p + i) << ": ";

        // Print hex bytes
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < len)
            {
                std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(p[i + j]) << " ";
            }
            else
            {
                std::cout << "   ";
            }
        }

        std::cout << " | ";

        // Print ASCII representation
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < len)
            {
                unsigned char c = p[i + j];
                if (c >= 32 && c <= 126)
                {
                    std::cout << c;
                }
                else
                {
                    std::cout << ".";
                }
            }
            else
            {
                std::cout << " ";
            }
        }

        std::cout << std::endl;
    }

    std::cout << std::dec << std::setfill(' '); // Reset to decimal
}

/**
 * @brief Demonstrates Windows system calls
 *
 * System calls are the interface between user mode and kernel mode.
 * They allow user-mode applications to request services from the kernel.
 */
void demonstrate_system_calls()
{
    std::cout << "Windows system calls are the interface between user mode and kernel mode." << std::endl;
    std::cout << "They allow user-mode applications to request services from the kernel." << std::endl;
    std::cout << std::endl;

    std::cout << "System call flow:" << std::endl;
    std::cout << "1. User-mode application calls a Win32 API function (e.g., CreateFile)" << std::endl;
    std::cout << "2. The Win32 API function prepares parameters and calls a Native API function (e.g., NtCreateFile)" << std::endl;
    std::cout << "3. The Native API function executes a system call instruction (e.g., syscall or int 2Eh)" << std::endl;
    std::cout << "4. The CPU switches to kernel mode and executes the corresponding kernel function" << std::endl;
    std::cout << "5. The kernel function performs the requested operation and returns to user mode" << std::endl;
    std::cout << std::endl;

    // Demonstrate a system call using the Native API
    std::cout << "Demonstrating a system call using the Native API:" << std::endl;

    // Get the address of NtQuerySystemInformation
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL)
    {
        std::cerr << "Failed to get handle to ntdll.dll. Error: " << GetLastError() << std::endl;
        return;
    }

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL)
    {
        std::cerr << "Failed to get address of NtQuerySystemInformation. Error: " << GetLastError() << std::endl;
        return;
    }

    // Query basic system information
    SYSTEM_BASIC_INFORMATION sbi;
    ULONG returnLength;
    NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), &returnLength);

    if (status != 0)
    {
        std::cerr << "NtQuerySystemInformation failed. Status: " << std::hex << status << std::dec << std::endl;
        return;
    }

    std::cout << "System information retrieved successfully:" << std::endl;
    std::cout << "  Page size: " << sbi.PageSize << " bytes" << std::endl;
    std::cout << "  Number of physical pages: " << sbi.NumberOfPhysicalPages << std::endl;
    std::cout << "  Lowest physical page number: " << sbi.LowestPhysicalPageNumber << std::endl;
    std::cout << "  Highest physical page number: " << sbi.HighestPhysicalPageNumber << std::endl;
    std::cout << "  Allocation granularity: " << sbi.AllocationGranularity << " bytes" << std::endl;
    std::cout << "  Minimum user mode address: 0x" << std::hex << sbi.MinimumUserModeAddress << std::dec << std::endl;
    std::cout << "  Maximum user mode address: 0x" << std::hex << sbi.MaximumUserModeAddress << std::dec << std::endl;
    std::cout << "  Active processors mask: 0x" << std::hex << sbi.ActiveProcessorsAffinityMask << std::dec << std::endl;
    std::cout << "  Number of processors: " << sbi.NumberOfProcessors << std::endl;

    std::cout << std::endl;
    std::cout << "System call numbers:" << std::endl;
    std::cout << "- System call numbers are used by the syscall instruction to identify the kernel function" << std::endl;
    std::cout << "- They are stored in the System Service Descriptor Table (SSDT)" << std::endl;
    std::cout << "- The SSDT is a kernel data structure that maps system call numbers to kernel functions" << std::endl;
    std::cout << "- System call numbers can change between Windows versions" << std::endl;
    std::cout << "- Malware often hooks the SSDT to intercept system calls" << std::endl;

    std::cout << std::endl;
    std::cout << "Security implications:" << std::endl;
    std::cout << "- System calls can be hooked to intercept sensitive operations" << std::endl;
    std::cout << "- Direct system calls can bypass user-mode hooks" << std::endl;
    std::cout << "- Understanding system calls is crucial for developing exploits and evasion techniques" << std::endl;
}

/**
 * @brief Demonstrates Windows process internals
 *
 * This function explores the internal structures and mechanisms of Windows processes,
 * including the Process Environment Block (PEB) and other process-related structures.
 */
void demonstrate_process_internals()
{
    std::cout << "Windows processes are represented by various internal structures:" << std::endl;
    std::cout << "- EPROCESS: Kernel-mode process object" << std::endl;
    std::cout << "- PEB (Process Environment Block): User-mode process information" << std::endl;
    std::cout << "- Handle table: Tracks open handles in the process" << std::endl;
    std::cout << "- VAD (Virtual Address Descriptor) tree: Tracks memory allocations" << std::endl;
    std::cout << std::endl;

    // Get the current process PEB
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    std::cout << "Current process PEB information:" << std::endl;
    std::cout << "  PEB address: 0x" << std::hex << peb << std::dec << std::endl;
    std::cout << "  Image base address: 0x" << std::hex << peb->ImageBaseAddress << std::dec << std::endl;
    std::cout << "  Process heap address: 0x" << std::hex << peb->ProcessHeap << std::dec << std::endl;
    std::cout << "  Number of heaps: " << peb->NumberOfHeaps << std::endl;
    std::cout << "  Maximum number of heaps: " << peb->MaximumNumberOfHeaps << std::endl;
    std::cout << "  BeingDebugged flag: " << static_cast<int>(peb->BeingDebugged) << std::endl;

    // Get the process parameters
    RTL_USER_PROCESS_PARAMETERS *processParams = peb->ProcessParameters;

    std::cout << "  Command line: ";
    if (processParams && processParams->CommandLine.Buffer)
    {
        std::wcout << processParams->CommandLine.Buffer << std::endl;
    }
    else
    {
        std::cout << "(null)" << std::endl;
    }

    std::cout << "  Current directory: ";
    if (processParams && processParams->CurrentDirectory.DosPath.Buffer)
    {
        std::wcout << processParams->CurrentDirectory.DosPath.Buffer << std::endl;
    }
    else
    {
        std::cout << "(null)" << std::endl;
    }

    // Get the loader data
    PEB_LDR_DATA *ldrData = peb->Ldr;

    std::cout << "  Loaded modules:" << std::endl;
    if (ldrData)
    {
        LIST_ENTRY *moduleList = &ldrData->InMemoryOrderModuleList;
        LIST_ENTRY *entry = moduleList->Flink;

        while (entry != moduleList)
        {
            LDR_DATA_TABLE_ENTRY *module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (module->FullDllName.Buffer)
            {
                std::wcout << "    " << module->FullDllName.Buffer << " (0x" << std::hex << module->DllBase << ")" << std::dec << std::endl;
            }

            entry = entry->Flink;
        }
    }

    std::cout << std::endl;
    std::cout << "Process creation:" << std::endl;
    std::cout << "1. CreateProcess calls NtCreateUserProcess" << std::endl;
    std::cout << "2. NtCreateUserProcess creates an EPROCESS structure" << std::endl;
    std::cout << "3. Memory is allocated for the process address space" << std::endl;
    std::cout << "4. The executable is mapped into memory" << std::endl;
    std::cout << "5. The PEB and TEB are initialized" << std::endl;
    std::cout << "6. The initial thread is created" << std::endl;
    std::cout << "7. The process is added to the system process list" << std::endl;

    std::cout << std::endl;
    std::cout << "Security implications:" << std::endl;
    std::cout << "- The PEB contains valuable information for attackers" << std::endl;
    std::cout << "- The BeingDebugged flag can be used for anti-debugging" << std::endl;
    std::cout << "- The loader data can be used to enumerate loaded modules" << std::endl;
    std::cout << "- Process hollowing techniques modify the PEB to point to malicious code" << std::endl;
}

/**
 * @brief Demonstrates Windows thread internals
 *
 * This function explores the internal structures and mechanisms of Windows threads,
 * including the Thread Environment Block (TEB) and other thread-related structures.
 */
void demonstrate_thread_internals()
{
    std::cout << "Windows threads are represented by various internal structures:" << std::endl;
    std::cout << "- ETHREAD: Kernel-mode thread object" << std::endl;
    std::cout << "- TEB (Thread Environment Block): User-mode thread information" << std::endl;
    std::cout << "- CONTEXT: CPU register state" << std::endl;
    std::cout << "- Stack: Thread's execution stack" << std::endl;
    std::cout << std::endl;

    // Get the current thread TEB
    PTEB teb = NtCurrentTeb();

    std::cout << "Current thread TEB information:" << std::endl;
    std::cout << "  TEB address: 0x" << std::hex << teb << std::dec << std::endl;
    std::cout << "  Process ID: " << teb->ClientId.UniqueProcess << std::endl;
    std::cout << "  Thread ID: " << teb->ClientId.UniqueThread << std::endl;
    std::cout << "  Stack base: 0x" << std::hex << teb->NtTib.StackBase << std::dec << std::endl;
    std::cout << "  Stack limit: 0x" << std::hex << teb->NtTib.StackLimit << std::dec << std::endl;
    std::cout << "  PEB address: 0x" << std::hex << teb->ProcessEnvironmentBlock << std::dec << std::endl;
    std::cout << "  Last error value: " << teb->LastErrorValue << std::endl;

    // Get the thread local storage (TLS)
    std::cout << "  Thread Local Storage (TLS):" << std::endl;
    for (int i = 0; i < 64; i++)
    {
        if (teb->TlsSlots[i] != nullptr)
        {
            std::cout << "    Slot " << i << ": 0x" << std::hex << teb->TlsSlots[i] << std::dec << std::endl;
        }
    }

    std::cout << std::endl;
    std::cout << "Thread creation:" << std::endl;
    std::cout << "1. CreateThread calls NtCreateThread" << std::endl;
    std::cout << "2. NtCreateThread creates an ETHREAD structure" << std::endl;
    std::cout << "3. Memory is allocated for the thread stack" << std::endl;
    std::cout << "4. The TEB is initialized" << std::endl;
    std::cout << "5. The initial CONTEXT is set up" << std::endl;
    std::cout << "6. The thread is added to the process's thread list" << std::endl;

    std::cout << std::endl;
    std::cout << "Thread scheduling:" << std::endl;
    std::cout << "- Windows uses a preemptive, priority-based scheduling algorithm" << std::endl;
    std::cout << "- Each thread has a base priority and a dynamic priority" << std::endl;
    std::cout << "- The scheduler selects the highest-priority ready thread to run" << std::endl;
    std::cout << "- Threads can be in various states: Running, Ready, Waiting, Terminated" << std::endl;

    std::cout << std::endl;
    std::cout << "Security implications:" << std::endl;
    std::cout << "- Thread injection can be used to execute code in another process" << std::endl;
    std::cout << "- The TEB contains sensitive information like the stack address" << std::endl;
    std::cout << "- Thread context manipulation can be used for code execution" << std::endl;
    std::cout << "- APC (Asynchronous Procedure Call) injection uses thread mechanisms" << std::endl;
}

/**
 * @brief Demonstrates Windows memory internals
 *
 * This function explores the internal structures and mechanisms of Windows memory management,
 * including virtual memory, physical memory, and memory-related data structures.
 */
void demonstrate_memory_internals()
{
    std::cout << "Windows memory management is based on virtual memory:" << std::endl;
    std::cout << "- Each process has its own virtual address space" << std::endl;
    std::cout << "- Virtual addresses are translated to physical addresses using page tables" << std::endl;
    std::cout << "- Memory is managed in pages (typically 4KB)" << std::endl;
    std::cout << "- The Memory Manager handles allocation, protection, and mapping" << std::endl;
    std::cout << std::endl;

    // Get system information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    std::cout << "System memory information:" << std::endl;
    std::cout << "  Page size: " << sysInfo.dwPageSize << " bytes" << std::endl;
    std::cout << "  Allocation granularity: " << sysInfo.dwAllocationGranularity << " bytes" << std::endl;
    std::cout << "  Minimum application address: 0x" << std::hex << sysInfo.lpMinimumApplicationAddress << std::dec << std::endl;
    std::cout << "  Maximum application address: 0x" << std::hex << sysInfo.lpMaximumApplicationAddress << std::dec << std::endl;
    std::cout << "  Number of processors: " << sysInfo.dwNumberOfProcessors << std::endl;

    // Get memory status
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    std::cout << "  Memory usage: " << memStatus.dwMemoryLoad << "%" << std::endl;
    std::cout << "  Total physical memory: " << memStatus.ullTotalPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "  Available physical memory: " << memStatus.ullAvailPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "  Total virtual memory: " << memStatus.ullTotalVirtual / (1024 * 1024) << " MB" << std::endl;
    std::cout << "  Available virtual memory: " << memStatus.ullAvailVirtual / (1024 * 1024) << " MB" << std::endl;

    // Demonstrate virtual memory allocation
    std::cout << std::endl;
    std::cout << "Demonstrating virtual memory allocation:" << std::endl;

    // Allocate memory
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        std::cerr << "Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "  Allocated 4096 bytes at address: 0x" << std::hex << mem << std::dec << std::endl;

    // Get memory information
    MEMORY_BASIC_INFORMATION memInfo;
    if (VirtualQuery(mem, &memInfo, sizeof(memInfo)) == 0)
    {
        std::cerr << "Failed to query memory information. Error: " << GetLastError() << std::endl;
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }

    std::cout << "  Memory information:" << std::endl;
    std::cout << "    Base address: 0x" << std::hex << memInfo.BaseAddress << std::dec << std::endl;
    std::cout << "    Allocation base: 0x" << std::hex << memInfo.AllocationBase << std::dec << std::endl;
    std::cout << "    Region size: " << memInfo.RegionSize << " bytes" << std::endl;

    std::cout << "    State: ";
    switch (memInfo.State)
    {
    case MEM_COMMIT:
        std::cout << "MEM_COMMIT";
        break;
    case MEM_RESERVE:
        std::cout << "MEM_RESERVE";
        break;
    case MEM_FREE:
        std::cout << "MEM_FREE";
        break;
    default:
        std::cout << "Unknown (" << memInfo.State << ")";
        break;
    }
    std::cout << std::endl;

    std::cout << "    Protection: ";
    switch (memInfo.Protect)
    {
    case PAGE_READONLY:
        std::cout << "PAGE_READONLY";
        break;
    case PAGE_READWRITE:
        std::cout << "PAGE_READWRITE";
        break;
    case PAGE_EXECUTE:
        std::cout << "PAGE_EXECUTE";
        break;
    case PAGE_EXECUTE_READ:
        std::cout << "PAGE_EXECUTE_READ";
        break;
    case PAGE_EXECUTE_READWRITE:
        std::cout << "PAGE_EXECUTE_READWRITE";
        break;
    case PAGE_NOACCESS:
        std::cout << "PAGE_NOACCESS";
        break;
    default:
        std::cout << "Other (" << memInfo.Protect << ")";
        break;
    }
    std::cout << std::endl;

    // Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(mem, 4096, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cerr << "Failed to change memory protection. Error: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "  Changed memory protection to PAGE_EXECUTE_READWRITE" << std::endl;
    }

    // Free memory
    if (!VirtualFree(mem, 0, MEM_RELEASE))
    {
        std::cerr << "Failed to free memory. Error: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "  Freed memory" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Memory-mapped files:" << std::endl;
    std::cout << "- Files can be mapped into memory using CreateFileMapping and MapViewOfFile" << std::endl;
    std::cout << "- This allows direct access to file contents through memory operations" << std::endl;
    std::cout << "- Memory-mapped files are used for efficient file I/O and shared memory" << std::endl;

    std::cout << std::endl;
    std::cout << "Security implications:" << std::endl;
    std::cout << "- Memory permissions can be bypassed using techniques like ROP" << std::endl;
    std::cout << "- Memory scanning is used by security products to detect malware" << std::endl;
    std::cout << "- Memory manipulation can be used for code injection and hooking" << std::endl;
    std::cout << "- Memory forensics is a valuable technique for malware analysis" << std::endl;
}

/**
 * @brief Demonstrates Windows handle table
 *
 * This function explores the Windows handle table, which is used to track
 * open handles to kernel objects in a process.
 */
void demonstrate_handle_table()
{
    std::cout << "The Windows handle table tracks open handles to kernel objects:" << std::endl;
    std::cout << "- Each process has its own handle table" << std::endl;
    std::cout << "- Handles are process-specific identifiers for kernel objects" << std::endl;
    std::cout << "- The handle table maps handle values to object pointers" << std::endl;
    std::cout << "- Objects are reference-counted and freed when all handles are closed" << std::endl;
    std::cout << std::endl;

    // Get the current process handle
    HANDLE processHandle = GetCurrentProcess();

    // Get the handle count
    DWORD handleCount = 0;
    if (!GetProcessHandleCount(processHandle, &handleCount))
    {
        std::cerr << "Failed to get handle count. Error: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "Current process handle count: " << handleCount << std::endl;

    // Enumerate handles using NtQuerySystemInformation
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL)
    {
        std::cerr << "Failed to get handle to ntdll.dll. Error: " << GetLastError() << std::endl;
        return;
    }

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL)
    {
        std::cerr << "Failed to get address of NtQuerySystemInformation. Error: " << GetLastError() << std::endl;
        return;
    }

    // First call to get the required buffer size
    ULONG bufferSize = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, NULL, 0, &bufferSize);

    if (status != 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
    {
        std::cerr << "Unexpected status from NtQuerySystemInformation. Status: " << std::hex << status << std::dec << std::endl;
        return;
    }

    // Allocate buffer
    std::vector<BYTE> buffer(bufferSize);

    // Second call to get the actual data
    status = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), bufferSize, &bufferSize);

    if (status != 0)
    {
        std::cerr << "NtQuerySystemInformation failed. Status: " << std::hex << status << std::dec << std::endl;
        return;
    }

    // Parse the handle information
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer.data();
    DWORD currentProcessId = GetCurrentProcessId();

    std::cout << "Handles in current process (" << currentProcessId << "):" << std::endl;
    std::cout << "  Handle  | Type | Object Address  | Access Mask" << std::endl;
    std::cout << "---------|------|----------------|------------" << std::endl;

    int count = 0;
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        if (handleInfo->Handles[i].ProcessId == currentProcessId)
        {
            std::cout << "  " << std::setw(6) << std::hex << handleInfo->Handles[i].Handle << " | "
                      << std::setw(4) << static_cast<int>(handleInfo->Handles[i].ObjectTypeNumber) << " | "
                      << std::setw(14) << handleInfo->Handles[i].Object << " | "
                      << std::setw(10) << handleInfo->Handles[i].GrantedAccess << std::dec << std::endl;

            count++;
            if (count >= 20)
            {
                std::cout << "  ... (more handles not shown)" << std::endl;
                break;
            }
        }
    }

    std::cout << std::endl;
    std::cout << "Handle inheritance:" << std::endl;
    std::cout << "- Handles can be marked as inheritable" << std::endl;
    std::cout << "- Inheritable handles are duplicated into child processes" << std::endl;
    std::cout << "- This allows parent and child processes to share objects" << std::endl;

    std::cout << std::endl;
    std::cout << "Handle duplication:" << std::endl;
    std::cout << "- DuplicateHandle can create a new handle to the same object" << std::endl;
    std::cout << "- This can be used to share objects between processes" << std::endl;
    std::cout << "- The new handle can have different access rights" << std::endl;

    std::cout << std::endl;
    std::cout << "Security implications:" << std::endl;
    std::cout << "- Handle leaks can cause resource exhaustion" << std::endl;
    std::cout << "- Handle hijacking can be used to gain access to protected objects" << std::endl;
    std::cout << "- Handle table scanning can reveal sensitive information" << std::endl;
    std::cout << "- Handle duplication can be used for privilege escalation" << std::endl;
}
