/**
* @file memory_module_loader.c
* @brief Demonstrates loading a DLL from memory using the MemoryModule technique
* 
* This file implements a memory module loader that can load a DLL entirely from memory
* without touching disk or using the standard Windows loader APIs. It uses a technique
* similar to the MemoryModule library by Joachim Bauch.
* 
* WARNING: This code is for educational purposes only. Do not use these techniques
* to bypass security controls without proper authorization.
* 
* Compilation (MSYS2/MinGW):
* gcc -std=c11 memory_module_loader.c -o memory_module_loader.exe
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

// Define the structure for the memory module
typedef struct {
    PIMAGE_NT_HEADERS ntHeaders;
    PVOID codeBase;
    HMODULE* modules;
    DWORD numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    PVOID* procs;
    DWORD numProcs;
} MEMORYMODULE, *PMEMORYMODULE;

// Function prototypes
BOOL MapDLLToMemory(const char* filePath, PVOID* baseAddress, PDWORD fileSize);
PMEMORYMODULE MemoryLoadLibrary(const void* data, size_t size);
FARPROC MemoryGetProcAddress(PMEMORYMODULE module, const char* name);
void MemoryFreeLibrary(PMEMORYMODULE module);
BOOL BuildImportTable(PMEMORYMODULE module);
BOOL FinalizeSections(PMEMORYMODULE module);
BOOL PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta);
BOOL CopySections(const void* data, PIMAGE_NT_HEADERS ntHeaders, PMEMORYMODULE module);
PVOID GetVAFromRVA(DWORD rva, PVOID moduleBase);

/**
* @brief Main function that demonstrates the memory module loader
*/
int main(int argc, char* argv[]) {
    printf("=== Memory Module Loader Demonstration ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <DLL path>\n", argv[0]);
        return 1;
    }
    
    const char* dllPath = argv[1];
    printf("DLL path: %s\n", dllPath);
    
    // Map the DLL into memory
    PVOID dllBuffer = NULL;
    DWORD dllSize = 0;
    if (!MapDLLToMemory(dllPath, &dllBuffer, &dllSize)) {
        printf("Error: Could not map DLL to memory\n");
        return 1;
    }
    
    printf("DLL mapped to memory at 0x%p (Size: %u bytes)\n", dllBuffer, dllSize);
    
    // Load the DLL from memory
    PMEMORYMODULE memoryModule = MemoryLoadLibrary(dllBuffer, dllSize);
    if (!memoryModule) {
        printf("Error: Could not load DLL from memory\n");
        free(dllBuffer);
        return 1;
    }
    
    printf("DLL loaded from memory at 0x%p\n", memoryModule->codeBase);
    
    // Get the address of a function from the DLL
    if (argc >= 3) {
        const char* functionName = argv[2];
        printf("Looking for function: %s\n", functionName);
        
        FARPROC function = MemoryGetProcAddress(memoryModule, functionName);
        if (function) {
            printf("Function %s found at 0x%p\n", functionName, function);
            
            // Call the function if it has no parameters and returns void
            printf("Calling function %s...\n", functionName);
            typedef void (*VoidFunc)(void);
            ((VoidFunc)function)();
            printf("Function call completed\n");
        } else {
            printf("Function %s not found\n", functionName);
        }
    }
    
    // Free the memory module
    MemoryFreeLibrary(memoryModule);
    printf("Memory module freed\n");
    
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
* @brief Loads a DLL from memory
* 
* @param data Pointer to the DLL in memory
* @param size Size of the DLL
* @return PMEMORYMODULE Pointer to the memory module, or NULL if failed
*/
PMEMORYMODULE MemoryLoadLibrary(const void* data, size_t size) {
    PMEMORYMODULE result = NULL;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PVOID codeBase = NULL;
    
    // Check parameters
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) {
        printf("Error: Invalid parameters\n");
        return NULL;
    }
    
    // Get the DOS header
    dosHeader = (PIMAGE_DOS_HEADER)data;
    
    // Check DOS signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid DOS signature\n");
        return NULL;
    }
    
    // Check if the NT headers are within the buffer
    if (dosHeader->e_lfanew >= size) {
        printf("Error: NT headers outside of buffer\n");
        return NULL;
    }
    
    // Get the NT headers
    ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)data + dosHeader->e_lfanew);
    
    // Check NT signature
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature\n");
        return NULL;
    }
    
    // Check if it's a 32-bit or 64-bit executable
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        printf("Error: Unsupported executable format\n");
        return NULL;
    }
    
    // Allocate memory for the module
    result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    if (!result) {
        printf("Error: Could not allocate memory for module\n");
        return NULL;
    }
    
    // Allocate memory for the image
    codeBase = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, 
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!codeBase) {
        printf("Error: Could not allocate memory for image (Error code: %lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, result);
        return NULL;
    }
    
    // Initialize the memory module
    result->codeBase = codeBase;
    result->ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)codeBase + dosHeader->e_lfanew);
    result->isDLL = (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    result->isRelocated = FALSE;
    
    // Copy the headers and sections
    if (!CopySections(data, ntHeaders, result)) {
        printf("Error: Could not copy sections\n");
        VirtualFree(codeBase, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, result);
        return NULL;
    }
    
    // Perform base relocation if necessary
    ptrdiff_t locationDelta = (ptrdiff_t)((BYTE*)codeBase - ntHeaders->OptionalHeader.ImageBase);
    if (locationDelta != 0) {
        if (!PerformBaseRelocation(result, locationDelta)) {
            printf("Warning: Could not perform base relocation\n");
        } else {
            result->isRelocated = TRUE;
        }
    } else {
        result->isRelocated = TRUE;
    }
    
    // Build the import table
    if (!BuildImportTable(result)) {
        printf("Warning: Could not build import table\n");
    }
    
    // Finalize the sections
    if (!FinalizeSections(result)) {
        printf("Warning: Could not finalize sections\n");
    }
    
    // Execute TLS callbacks
    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)GetVAFromRVA(
        result->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
        result->codeBase);
    if (tls) {
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callback) {
            while (*callback) {
                (*callback)((LPVOID)result->codeBase, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }
    
    // Execute DllMain if it's a DLL
    if (result->isDLL) {
        DWORD entryPointRVA = result->ntHeaders->OptionalHeader.AddressOfEntryPoint;
        if (entryPointRVA != 0) {
            PVOID entryPoint = (BYTE*)result->codeBase + entryPointRVA;
            
            typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
            DllMain_t DllMain = (DllMain_t)entryPoint;
            
            if (!DllMain((HINSTANCE)result->codeBase, DLL_PROCESS_ATTACH, NULL)) {
                printf("Warning: DllMain returned FALSE\n");
            } else {
                result->initialized = TRUE;
            }
        } else {
            result->initialized = TRUE;
        }
    } else {
        result->initialized = TRUE;
    }
    
    return result;
}

/**
* @brief Gets the address of a function from a memory module
* 
* @param module Pointer to the memory module
* @param name Name of the function
* @return FARPROC Address of the function, or NULL if not found
*/
FARPROC MemoryGetProcAddress(PMEMORYMODULE module, const char* name) {
    DWORD i, nameOrdinal;
    PIMAGE_EXPORT_DIRECTORY exports;
    PIMAGE_DATA_DIRECTORY directory;
    DWORD* nameRVAs;
    WORD* ordinals;
    DWORD* functionRVAs;
    
    // Check parameters
    if (!module || !name) {
        return NULL;
    }
    
    // Get the export directory
    directory = &module->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory->VirtualAddress == 0) {
        // DLL has no export table
        return NULL;
    }
    
    exports = (PIMAGE_EXPORT_DIRECTORY)GetVAFromRVA(directory->VirtualAddress, module->codeBase);
    if (!exports) {
        return NULL;
    }
    
    // Get the export tables
    nameRVAs = (DWORD*)GetVAFromRVA(exports->AddressOfNames, module->codeBase);
    ordinals = (WORD*)GetVAFromRVA(exports->AddressOfNameOrdinals, module->codeBase);
    functionRVAs = (DWORD*)GetVAFromRVA(exports->AddressOfFunctions, module->codeBase);
    
    // Check if the function is exported by name
    for (i = 0; i < exports->NumberOfNames; i++) {
        const char* exportName = (const char*)GetVAFromRVA(nameRVAs[i], module->codeBase);
        if (exportName && strcmp(name, exportName) == 0) {
            nameOrdinal = ordinals[i];
            DWORD functionRVA = functionRVAs[nameOrdinal];
            
            // Check if it's a forwarder
            if (functionRVA >= directory->VirtualAddress && 
                functionRVA < directory->VirtualAddress + directory->Size) {
                // It's a forwarder, not supported in this implementation
                return NULL;
            }
            
            return (FARPROC)GetVAFromRVA(functionRVA, module->codeBase);
        }
    }
    
    // Check if the function is exported by ordinal
    if ((DWORD)(uintptr_t)name <= 0xFFFF) {
        nameOrdinal = (DWORD)(uintptr_t)name - exports->Base;
        if (nameOrdinal < exports->NumberOfFunctions) {
            DWORD functionRVA = functionRVAs[nameOrdinal];
            
            // Check if it's a forwarder
            if (functionRVA >= directory->VirtualAddress && 
                functionRVA < directory->VirtualAddress + directory->Size) {
                // It's a forwarder, not supported in this implementation
                return NULL;
            }
            
            return (FARPROC)GetVAFromRVA(functionRVA, module->codeBase);
        }
    }
    
    // Function not found
    return NULL;
}

/**
* @brief Frees a memory module
* 
* @param module Pointer to the memory module
*/
void MemoryFreeLibrary(PMEMORYMODULE module) {
    if (!module) {
        return;
    }
    
    // Call DllMain with DLL_PROCESS_DETACH if the DLL was initialized
    if (module->initialized && module->isDLL) {
        DWORD entryPointRVA = module->ntHeaders->OptionalHeader.AddressOfEntryPoint;
        if (entryPointRVA != 0) {
            PVOID entryPoint = (BYTE*)module->codeBase + entryPointRVA;
            
            typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
            DllMain_t DllMain = (DllMain_t)entryPoint;
            
            DllMain((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, NULL);
        }
    }
    
    // Free the loaded modules
    if (module->modules) {
        for (DWORD i = 0; i < module->numModules; i++) {
            if (module->modules[i]) {
                FreeLibrary(module->modules[i]);
            }
        }
        
        HeapFree(GetProcessHeap(), 0, module->modules);
    }
    
    // Free the function pointers
    if (module->procs) {
        HeapFree(GetProcessHeap(), 0, module->procs);
    }
    
    // Free the allocated memory
    if (module->codeBase) {
        VirtualFree(module->codeBase, 0, MEM_RELEASE);
    }
    
    // Free the module structure
    HeapFree(GetProcessHeap(), 0, module);
}

/**
* @brief Builds the import table for a memory module
* 
* @param module Pointer to the memory module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL BuildImportTable(PMEMORYMODULE module) {
    PIMAGE_DATA_DIRECTORY directory;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    DWORD numModules = 0;
    
    // Get the import directory
    directory = &module->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory->VirtualAddress == 0) {
        // DLL has no import table
        return TRUE;
    }
    
    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetVAFromRVA(directory->VirtualAddress, module->codeBase);
    if (!importDesc) {
        return FALSE;
    }
    
    // Count the number of imported DLLs
    while (importDesc->Name) {
        numModules++;
        importDesc++;
    }
    
    // Allocate memory for the module handles
    module->modules = (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
                                         numModules * sizeof(HMODULE));
    if (!module->modules) {
        return FALSE;
    }
    
    module->numModules = numModules;
    
    // Reset the import descriptor
    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetVAFromRVA(directory->VirtualAddress, module->codeBase);
    
    // Load each imported DLL and resolve its functions
    for (DWORD i = 0; i < numModules; i++) {
        const char* dllName = (const char*)GetVAFromRVA(importDesc->Name, module->codeBase);
        HMODULE hDll = LoadLibraryA(dllName);
        
        if (!hDll) {
            printf("Warning: Could not load DLL: %s (Error code: %lu)\n", dllName, GetLastError());
            importDesc++;
            continue;
        }
        
        module->modules[i] = hDll;
        
        // Get the IAT (Import Address Table)
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)GetVAFromRVA(importDesc->FirstThunk, 
                                                                    module->codeBase);
        
        // Get the INT (Import Name Table)
        PIMAGE_THUNK_DATA thunkINT = (PIMAGE_THUNK_DATA)GetVAFromRVA(
            importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk,
            module->codeBase);
        
        // Resolve each imported function
        while (thunkINT->u1.AddressOfData) {
            FARPROC function = NULL;
            
            // Check if the import is by ordinal
            if (IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
                // Import by ordinal
                WORD ordinal = (WORD)IMAGE_ORDINAL(thunkINT->u1.Ordinal);
                function = GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ordinal);
                
                if (!function) {
                    printf("Warning: Could not import function by ordinal: %u from %s (Error code: %lu)\n", 
                           ordinal, dllName, GetLastError());
                }
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)GetVAFromRVA(
                    thunkINT->u1.AddressOfData, module->codeBase);
                
                function = GetProcAddress(hDll, (LPCSTR)importByName->Name);
                
                if (!function) {
                    printf("Warning: Could not import function by name: %s from %s (Error code: %lu)\n", 
                           importByName->Name, dllName, GetLastError());
                }
            }
            
            // Update the IAT with the function address
            thunkIAT->u1.Function = (ULONGLONG)function;
            
            // Move to the next function
            thunkIAT++;
            thunkINT++;
        }
        
        // Move to the next DLL
        importDesc++;
    }
    
    return TRUE;
}

/**
* @brief Finalizes the sections of a memory module
* 
* @param module Pointer to the memory module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL FinalizeSections(PMEMORYMODULE module) {
    PIMAGE_SECTION_HEADER section;
    DWORD i, oldProtect;
    
    // Get the first section
    section = IMAGE_FIRST_SECTION(module->ntHeaders);
    
    // Change the protection of each section
    for (i = 0; i < module->ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionSize = section[i].SizeOfRawData;
        if (sectionSize == 0) {
            // Section without data
            if (section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                // BSS section
                sectionSize = module->ntHeaders->OptionalHeader.SizeOfUninitializedData;
                if (sectionSize == 0) {
                    // No BSS section
                    continue;
                }
            } else {
                // Empty section
                continue;
            }
        }
        
        // Determine the protection flags
        DWORD protect = 0;
        BOOL executable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL readable = (section[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL writeable = (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        
        if (executable) {
            protect = writeable ? PAGE_EXECUTE_READWRITE : (readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
        } else {
            protect = writeable ? PAGE_READWRITE : (readable ? PAGE_READONLY : PAGE_NOACCESS);
        }
        
        // Change the protection
        PVOID sectionAddress = (BYTE*)module->codeBase + section[i].VirtualAddress;
        if (!VirtualProtect(sectionAddress, sectionSize, protect, &oldProtect)) {
            printf("Warning: Could not change protection of section %s (Error code: %lu)\n", 
                   section[i].Name, GetLastError());
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
* @brief Performs base relocation for a memory module
* 
* @param module Pointer to the memory module
* @param delta Difference between preferred and actual base address
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta) {
    PIMAGE_DATA_DIRECTORY directory;
    PIMAGE_BASE_RELOCATION relocation;
    
    // Get the relocation directory
    directory = &module->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory->VirtualAddress == 0) {
        // DLL has no relocation table
        return delta == 0;
    }
    
    relocation = (PIMAGE_BASE_RELOCATION)GetVAFromRVA(directory->VirtualAddress, module->codeBase);
    if (!relocation) {
        return FALSE;
    }
    
    // Process each relocation block
    while (relocation->VirtualAddress) {
        PVOID dest = (BYTE*)module->codeBase + relocation->VirtualAddress;
        DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD relInfo = (PWORD)((BYTE*)relocation + sizeof(IMAGE_BASE_RELOCATION));
        
        // Process each entry
        for (DWORD i = 0; i < count; i++) {
            DWORD type = relInfo[i] >> 12;
            DWORD offset = relInfo[i] & 0xFFF;
            
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Skip
                    break;
                
                case IMAGE_REL_BASED_HIGHLOW:
                    // 32-bit relocation
                    *((DWORD*)((BYTE*)dest + offset)) += (DWORD)delta;
                    break;
                
                case IMAGE_REL_BASED_DIR64:
                    // 64-bit relocation
                    *((ULONGLONG*)((BYTE*)dest + offset)) += (ULONGLONG)delta;
                    break;
                
                default:
                    printf("Warning: Unsupported relocation type: %u\n", type);
                    break;
            }
        }
        
        // Move to the next block
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }
    
    return TRUE;
}

/**
* @brief Copies the sections of a PE file to memory
* 
* @param data Pointer to the PE file in memory
* @param ntHeaders Pointer to the NT headers
* @param module Pointer to the memory module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL CopySections(const void* data, PIMAGE_NT_HEADERS ntHeaders, PMEMORYMODULE module) {
    PIMAGE_SECTION_HEADER section;
    DWORD i;
    
    // Copy the headers
    memcpy(module->codeBase, data, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    // Get the first section
    section = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Copy each section
    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID dest = (BYTE*)module->codeBase + section[i].VirtualAddress;
        PVOID src = (BYTE*)data + section[i].PointerToRawData;
        DWORD size = min(section[i].SizeOfRawData, section[i].Misc.VirtualSize);
        
        if (size > 0) {
            memcpy(dest, src, size);
        }
        
        // If the section is larger than the raw data (contains BSS)
        if (size < section[i].Misc.VirtualSize) {
            // Clear the rest of the section
            memset((BYTE*)dest + size, 0, section[i].Misc.VirtualSize - size);
        }
        
        section++;
    }
    
    return TRUE;
}

/**
* @brief Converts a relative virtual address to a virtual address
* 
* @param rva Relative virtual address
* @param moduleBase Base address of the module
* @return PVOID Virtual address
*/
PVOID GetVAFromRVA(DWORD rva, PVOID moduleBase) {
    if (rva == 0) {
        return NULL;
    }
    
    return (BYTE*)moduleBase + rva;
}

/**
* Additional Notes:
* 
* 1. Memory Module Technique:
*    - The memory module technique allows loading a DLL entirely from memory
*    - It bypasses the standard Windows loader and can evade detection by security products
*    - This implementation is based on the MemoryModule library by Joachim Bauch
* 
* 2. PE Loading Process:
*    - The PE loading process involves parsing the PE headers, allocating memory, copying sections,
*      fixing relocations, and resolving imports
*    - The memory module technique performs all these steps manually
* 
* 3. Sections:
*    - PE files are divided into sections, each with its own characteristics
*    - Common sections include .text (code), .data (initialized data), .rdata (read-only data),
*      and .bss (uninitialized data)
*    - Each section can have different memory protection flags
* 
* 4. Imports:
*    - Imports are functions that the DLL uses from other DLLs
*    - The import directory contains information about which DLLs and functions are needed
*    - Resolving imports involves loading the required DLLs and getting the addresses of the functions
* 
* 5. Relocations:
*    - Relocations are necessary when a module is loaded at a different base address than expected
*    - The relocation directory contains information about which addresses need to be adjusted
*    - Different types of relocations exist for different architectures (32-bit, 64-bit)
* 
* 6. Security Implications:
*    - The memory module technique is often used by malware to evade detection
*    - It can bypass DLL load monitoring and other security controls
*    - Understanding these techniques is important for both offensive and defensive security
*/

