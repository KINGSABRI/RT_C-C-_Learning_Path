/**
* @file custom_pe_loader.c
* @brief Demonstrates a custom PE (Portable Executable) loader implementation
* 
* This file implements a custom PE loader that can load and execute Windows PE files
* directly from memory without using the standard Windows loader. This technique is
* often used to evade detection by security products that monitor standard loading
* mechanisms.
* 
* WARNING: This code is for educational purposes only. Do not use these techniques
* to bypass security controls without proper authorization.
* 
* Compilation (MSYS2/MinGW):
* gcc -std=c11 custom_pe_loader.c -o custom_pe_loader.exe
* 
* Red Team Applications:
* - Evading detection by security products
* - Loading executables from memory without touching disk
* - Bypassing application whitelisting
* - Understanding how malware loaders work
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Function prototypes
BOOL MapPEFileToMemory(const char* filePath, PVOID* baseAddress, PDWORD fileSize);
BOOL LoadPEFromMemory(PVOID peBuffer, PVOID* moduleBase);
BOOL RelocateImage(PVOID peBuffer, PVOID moduleBase);
BOOL ResolveImports(PVOID peBuffer, PVOID moduleBase);
BOOL ExecutePE(PVOID moduleBase, PVOID peBuffer);
BOOL FixImageRelocations(PVOID moduleBase, PVOID peBuffer, ULONGLONG delta);
BOOL FixImageImports(PVOID moduleBase, PVOID peBuffer);
DWORD GetRVAFromVA(PVOID address, PVOID moduleBase);
PVOID GetVAFromRVA(DWORD rva, PVOID moduleBase);

/**
* @brief Main function that demonstrates the custom PE loader
*/
int main(int argc, char* argv[]) {
    printf("=== Custom PE Loader Demonstration ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <PE file path>\n", argv[0]);
        return 1;
    }
    
    const char* filePath = argv[1];
    printf("Loading PE file: %s\n", filePath);
    
    // Map the PE file into memory
    PVOID peBuffer = NULL;
    DWORD fileSize = 0;
    if (!MapPEFileToMemory(filePath, &peBuffer, &fileSize)) {
        printf("Failed to map PE file to memory\n");
        return 1;
    }
    
    printf("PE file mapped to memory at 0x%p (Size: %u bytes)\n", peBuffer, fileSize);
    
    // Load the PE from memory
    PVOID moduleBase = NULL;
    if (!LoadPEFromMemory(peBuffer, &moduleBase)) {
        printf("Failed to load PE from memory\n");
        free(peBuffer);
        return 1;
    }
    
    printf("PE loaded to memory at 0x%p\n", moduleBase);
    
    // Execute the PE
    if (!ExecutePE(moduleBase, peBuffer)) {
        printf("Failed to execute PE\n");
        VirtualFree(moduleBase, 0, MEM_RELEASE);
        free(peBuffer);
        return 1;
    }
    
    // Clean up
    VirtualFree(moduleBase, 0, MEM_RELEASE);
    free(peBuffer);
    
    printf("PE execution completed\n");
    
    return 0;
}

/**
* @brief Maps a PE file from disk into memory
* 
* @param filePath Path to the PE file
* @param baseAddress Pointer to receive the base address of the mapped file
* @param fileSize Pointer to receive the size of the mapped file
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL MapPEFileToMemory(const char* filePath, PVOID* baseAddress, PDWORD fileSize) {
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
    
    // Set output parameters
    *baseAddress = buffer;
    *fileSize = size;
    
    return TRUE;
}

/**
* @brief Loads a PE file from memory into executable memory
* 
* @param peBuffer Pointer to the PE file in memory
* @param moduleBase Pointer to receive the base address of the loaded module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL LoadPEFromMemory(PVOID peBuffer, PVOID* moduleBase) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)peBuffer + dosHeader->e_lfanew);
    
    // Get the size of the image
    DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    // Allocate memory for the image
    PVOID imageBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        printf("Error: Could not allocate memory for image (Error code: %lu)\n", GetLastError());
        return FALSE;
    }
    
    printf("Allocated memory for image at 0x%p (Size: %u bytes)\n", imageBase, imageSize);
    
    // Copy the headers
    memcpy(imageBase, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    // Copy each section
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionDestination = (BYTE*)imageBase + sectionHeader[i].VirtualAddress;
        PVOID sectionSource = (BYTE*)peBuffer + sectionHeader[i].PointerToRawData;
        DWORD sectionSize = min(sectionHeader[i].SizeOfRawData, sectionHeader[i].Misc.VirtualSize);
        
        memcpy(sectionDestination, sectionSource, sectionSize);
        
        printf("Copied section %s to 0x%p (Size: %u bytes)\n", 
               sectionHeader[i].Name, sectionDestination, sectionSize);
    }
    
    // Perform relocations if necessary
    if (ntHeaders->OptionalHeader.ImageBase != (ULONGLONG)imageBase) {
        if (!RelocateImage(peBuffer, imageBase)) {
            printf("Warning: Failed to relocate image\n");
        }
    }
    
    // Resolve imports
    if (!ResolveImports(peBuffer, imageBase)) {
        printf("Warning: Failed to resolve imports\n");
    }
    
    // Set output parameter
    *moduleBase = imageBase;
    
    return TRUE;
}

/**
* @brief Relocates the image if it was loaded at a different base address
* 
* @param peBuffer Pointer to the PE file in memory
* @param moduleBase Base address of the loaded module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL RelocateImage(PVOID peBuffer, PVOID moduleBase) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)peBuffer + dosHeader->e_lfanew);
    
    // Calculate the delta between the preferred base address and the actual base address
    ULONGLONG delta = (ULONGLONG)moduleBase - ntHeaders->OptionalHeader.ImageBase;
    
    printf("Relocating image (Delta: 0x%llx)\n", delta);
    
    // If there's no delta, no need to relocate
    if (delta == 0) {
        printf("No relocation needed (Delta is 0)\n");
        return TRUE;
    }
    
    // Check if the image has a relocation directory
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 ||
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
        printf("Warning: Image has no relocation directory\n");
        return FALSE;
    }
    
    // Fix the relocations
    return FixImageRelocations(moduleBase, peBuffer, delta);
}

/**
* @brief Resolves the imports of the loaded module
* 
* @param peBuffer Pointer to the PE file in memory
* @param moduleBase Base address of the loaded module
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL ResolveImports(PVOID peBuffer, PVOID moduleBase) {
    printf("Resolving imports\n");
    
    // Fix the imports
    return FixImageImports(moduleBase, peBuffer);
}

/**
* @brief Executes the loaded PE file
* 
* @param moduleBase Base address of the loaded module
* @param peBuffer Pointer to the PE file in memory
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL ExecutePE(PVOID moduleBase, PVOID peBuffer) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)peBuffer + dosHeader->e_lfanew);
    
    // Get the entry point
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    PVOID entryPoint = (BYTE*)moduleBase + entryPointRVA;
    
    printf("Executing PE at entry point 0x%p (RVA: 0x%08X)\n", entryPoint, entryPointRVA);
    
    // For DLLs, call DllMain
    if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
        DllMain_t DllMain = (DllMain_t)entryPoint;
        
        return DllMain((HINSTANCE)moduleBase, DLL_PROCESS_ATTACH, NULL);
    }
    // For executables, call the entry point
    else {
        typedef int (WINAPI *EntryPoint_t)(void);
        EntryPoint_t EntryPoint = (EntryPoint_t)entryPoint;
        
        EntryPoint();
        return TRUE;
    }
}

/**
* @brief Fixes the relocations of the loaded module
* 
* @param moduleBase Base address of the loaded module
* @param peBuffer Pointer to the PE file in memory
* @param delta Difference between preferred and actual base address
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL FixImageRelocations(PVOID moduleBase, PVOID peBuffer, ULONGLONG delta) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    
    // Get the relocation directory
    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    // If there's no relocation directory, return
    if (relocRVA == 0 || relocSize == 0) {
        return TRUE;
    }
    
    // Get the first relocation block
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)moduleBase + relocRVA);
    
    // Process each relocation block
    while (relocation->VirtualAddress != 0) {
        // Get the number of entries in this block
        DWORD entriesCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        // Get the first entry
        PWORD entries = (PWORD)((BYTE*)relocation + sizeof(IMAGE_BASE_RELOCATION));
        
        // Process each entry
        for (DWORD i = 0; i < entriesCount; i++) {
            // Get the type and offset
            DWORD type = entries[i] >> 12;
            DWORD offset = entries[i] & 0xFFF;
            
            // Calculate the address to fix
            PVOID address = (BYTE*)moduleBase + relocation->VirtualAddress + offset;
            
            // Apply the relocation based on type
            switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    // 32-bit relocation
                    *(DWORD*)address += (DWORD)delta;
                    break;
                
                case IMAGE_REL_BASED_DIR64:
                    // 64-bit relocation
                    *(ULONGLONG*)address += delta;
                    break;
                
                case IMAGE_REL_BASED_ABSOLUTE:
                    // No relocation needed
                    break;
                
                default:
                    printf("Warning: Unsupported relocation type: %u\n", type);
                    break;
            }
        }
        
        // Move to the next relocation block
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }
    
    return TRUE;
}

/**
* @brief Fixes the imports of the loaded module
* 
* @param moduleBase Base address of the loaded module
* @param peBuffer Pointer to the PE file in memory
* @return BOOL TRUE if successful, FALSE otherwise
*/
BOOL FixImageImports(PVOID moduleBase, PVOID peBuffer) {
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    
    // Get the import directory
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    // If there's no import directory, return
    if (importRVA == 0 || importSize == 0) {
        return TRUE;
    }
    
    // Get the first import descriptor
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)moduleBase + importRVA);
    
    // Process each import descriptor
    while (importDesc->Name != 0) {
        // Get the name of the DLL
        const char* dllName = (const char*)((BYTE*)moduleBase + importDesc->Name);
        
        // Load the DLL
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) {
            printf("Warning: Could not load DLL: %s (Error code: %lu)\n", dllName, GetLastError());
            importDesc++;
            continue;
        }
        
        printf("Loaded DLL: %s at 0x%p\n", dllName, hDll);
        
        // Get the IAT (Import Address Table)
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)moduleBase + importDesc->FirstThunk);
        
        // Get the INT (Import Name Table)
        PIMAGE_THUNK_DATA thunkINT = (PIMAGE_THUNK_DATA)((BYTE*)moduleBase + 
            (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
        
        // Process each function
        while (thunkINT->u1.AddressOfData != 0) {
            FARPROC functionAddress = NULL;
            
            // Check if the import is by ordinal
            if (IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
                // Import by ordinal
                WORD ordinal = (WORD)IMAGE_ORDINAL(thunkINT->u1.Ordinal);
                functionAddress = GetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ordinal);
                
                if (functionAddress) {
                    printf("  Imported function by ordinal: %u -> 0x%p\n", ordinal, functionAddress);
                } else {
                    printf("  Warning: Could not import function by ordinal: %u (Error code: %lu)\n", 
                           ordinal, GetLastError());
                }
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)moduleBase + 
                    thunkINT->u1.AddressOfData);
                
                functionAddress = GetProcAddress(hDll, (LPCSTR)importByName->Name);
                
                if (functionAddress) {
                    printf("  Imported function by name: %s -> 0x%p\n", importByName->Name, functionAddress);
                } else {
                    printf("  Warning: Could not import function by name: %s (Error code: %lu)\n", 
                           importByName->Name, GetLastError());
                }
            }
            
            // Update the IAT with the function address
            thunkIAT->u1.Function = (ULONGLONG)functionAddress;
            
            // Move to the next function
            thunkIAT++;
            thunkINT++;
        }
        
        // Move to the next import descriptor
        importDesc++;
    }
    
    return TRUE;
}

/**
* @brief Converts a virtual address to a relative virtual address
* 
* @param address Virtual address
* @param moduleBase Base address of the module
* @return DWORD Relative virtual address
*/
DWORD GetRVAFromVA(PVOID address, PVOID moduleBase) {
    return (DWORD)((BYTE*)address - (BYTE*)moduleBase);
}

/**
* @brief Converts a relative virtual address to a virtual address
* 
* @param rva Relative virtual address
* @param moduleBase Base address of the module
* @return PVOID Virtual address
*/
PVOID GetVAFromRVA(DWORD rva, PVOID moduleBase) {
    return (BYTE*)moduleBase + rva;
}

/**
* Additional Notes:
* 
* 1. PE File Format:
*    - PE (Portable Executable) is the file format used by Windows executables, DLLs, and other files
*    - It consists of headers, sections, and various data directories
*    - The headers include the DOS header, NT headers, and section headers
*    - The sections contain the actual code and data of the executable
* 
* 2. Custom PE Loading:
*    - Custom PE loading involves manually parsing the PE headers and loading the file into memory
*    - This bypasses the standard Windows loader and can evade detection by security products
*    - The process involves mapping the file, allocating memory, copying sections, fixing relocations,
*      and resolving imports
* 
* 3. Relocations:
*    - Relocations are necessary when a module is loaded at a different base address than expected
*    - The relocation directory contains information about which addresses need to be adjusted
*    - Different types of relocations exist for different architectures (32-bit, 64-bit)
* 
* 4. Imports:
*    - Imports are functions that the module uses from other DLLs
*    - The import directory contains information about which DLLs and functions are needed
*    - Resolving imports involves loading the required DLLs and getting the addresses of the functions
* 
* 5. Security Implications:
*    - Custom PE loading is often used by malware to evade detection
*    - It can bypass application whitelisting and other security controls
*    - Understanding these techniques is important for both offensive and defensive security
* 
* 6. Limitations of This Implementation:
*    - This implementation is simplified for educational purposes
*    - It does not handle all edge cases and may not work with all PE files
*    - A real-world implementation would need to be more robust
*/

