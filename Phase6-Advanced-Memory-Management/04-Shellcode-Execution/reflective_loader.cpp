#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>

// Red Team Focus: Reflective loading can be used to:
// 1. Load DLLs from memory without touching disk
// 2. Bypass application whitelisting
// 3. Evade detection by AV/EDR solutions
// 4. Implement fileless malware

// Simple PE parser class
class PEParser {
private:
    std::vector<unsigned char> peData;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeaders;
    bool isValid;

public:
    PEParser(const std::vector<unsigned char>& data) : peData(data), isValid(false) {
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "Invalid PE file: too small" << std::endl;
            return;
        }
        
        // Get the DOS header
        dosHeader = (PIMAGE_DOS_HEADER)peData.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid PE file: DOS signature not found" << std::endl;
            return;
        }
        
        // Get the NT headers
        ntHeaders = (PIMAGE_NT_HEADERS)(peData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid PE file: NT signature not found" << std::endl;
            return;
        }
        
        // Get the section headers
        sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
        
        isValid = true;
    }
    
    bool isValidPE() const {
        return isValid;
    }
    
    PIMAGE_DOS_HEADER getDosHeader() const {
        return dosHeader;
    }
    
    PIMAGE_NT_HEADERS getNtHeaders() const {
        return ntHeaders;
    }
    
    PIMAGE_SECTION_HEADER getSectionHeaders() const {
        return sectionHeaders;
    }
    
    DWORD getNumberOfSections() const {
        return ntHeaders->FileHeader.NumberOfSections;
    }
    
    DWORD getSizeOfImage() const {
        return ntHeaders->OptionalHeader.SizeOfImage;
    }
    
    DWORD getEntryPoint() const {
        return ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    
    DWORD getImageBase() const {
        return ntHeaders->OptionalHeader.ImageBase;
    }
    
    const std::vector<unsigned char>& getData() const {
        return peData;
    }
};

// Reflective loader class
class ReflectiveLoader {
private:
    PEParser peParser;
    void* mappedImage;
    bool loaded;

public:
    ReflectiveLoader(const std::vector<unsigned char>& peData) 
        : peParser(peData), mappedImage(NULL), loaded(false) {}
    
    ~ReflectiveLoader() {
        unload();
    }
    
    // Load the PE file into memory
    bool load() {
        if (!peParser.isValidPE()) {
            std::cerr << "Invalid PE file" << std::endl;
            return false;
        }
        
        // Allocate memory for the image
        DWORD sizeOfImage = peParser.getSizeOfImage();
        mappedImage = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mappedImage == NULL) {
            std::cerr << "Failed to allocate memory for image. Error: " << GetLastError() << std::endl;
            return false;
        }
        
        // Copy the headers
        memcpy(mappedImage, peParser.getData().data(), peParser.getNtHeaders()->OptionalHeader.SizeOfHeaders);
        
        // Copy the sections
        PIMAGE_SECTION_HEADER sectionHeader = peParser.getSectionHeaders();
        for (DWORD i = 0; i < peParser.getNumberOfSections(); ++i) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                void* sectionDestination = (BYTE*)mappedImage + sectionHeader[i].VirtualAddress;
                void* sectionSource = (BYTE*)peParser.getData().data() + sectionHeader[i].PointerToRawData;
                memcpy(sectionDestination, sectionSource, sectionHeader[i].SizeOfRawData);
            }
        }
        
        // Perform relocations
        if (!performRelocations()) {
            VirtualFree(mappedImage, 0, MEM_RELEASE);
            mappedImage = NULL;
            return false;
        }
        
        // Resolve imports
        if (!resolveImports()) {
            VirtualFree(mappedImage, 0, MEM_RELEASE);
            mappedImage = NULL;
            return false;
        }
        
        // Set memory protections
        if (!setMemoryProtections()) {
            VirtualFree(mappedImage, 0, MEM_RELEASE);
            mappedImage = NULL;
            return false;
        }
        
        loaded = true;
        std::cout << "PE file loaded at " << mappedImage << std::endl;
        return true;
    }
    
    // Perform relocations
    bool performRelocations() {
        // Calculate the delta between the preferred image base and the actual base
        DWORD_PTR delta = (DWORD_PTR)mappedImage - peParser.getImageBase();
        if (delta == 0) {
            // No relocations needed
            return true;
        }
        
        // Get the relocation directory
        PIMAGE_DATA_DIRECTORY relocDir = &peParser.getNtHeaders()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size == 0) {
            // No relocations
            return true;
        }
        
        // Process each relocation block
        DWORD_PTR relocBase = (DWORD_PTR)mappedImage + relocDir->VirtualAddress;
        DWORD relocSize = relocDir->Size;
        DWORD_PTR relocEnd = relocBase + relocSize;
        
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)relocBase;
        while ((DWORD_PTR)relocation < relocEnd && relocation->SizeOfBlock > 0) {
            DWORD_PTR pageRVA = relocation->VirtualAddress;
            DWORD entriesCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((DWORD_PTR)relocation + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < entriesCount; ++i) {
                WORD entry = entries[i];
                DWORD type = entry >> 12;
                DWORD offset = entry & 0xFFF;
                
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* address = (DWORD_PTR*)((DWORD_PTR)mappedImage + pageRVA + offset);
                    *address += delta;
                }
            }
            
            relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
        }
        
        return true;
    }
    
    // Resolve imports
    bool resolveImports() {
        // Get the import directory
        PIMAGE_DATA_DIRECTORY importDir = &peParser.getNtHeaders()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->Size == 0) {
            // No imports
            return true;
        }
        
        // Process each import descriptor
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)mappedImage + importDir->VirtualAddress);
        while (importDesc->Name != 0) {
            // Get the name of the DLL
            char* dllName = (char*)((DWORD_PTR)mappedImage + importDesc->Name);
            
            // Load the DLL
            HMODULE hDll = LoadLibraryA(dllName);
            if (hDll == NULL) {
                std::cerr << "Failed to load DLL: " << dllName << ". Error: " << GetLastError() << std::endl;
                return false;
            }
            
            // Process the import address table
            PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)mappedImage + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA thunkINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)mappedImage + importDesc->OriginalFirstThunk);
            
            while (thunkIAT->u1.AddressOfData != 0) {
                FARPROC functionAddress;
                
                // Check if the import is by ordinal
                if (IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
                    DWORD ordinal = IMAGE_ORDINAL(thunkINT->u1.Ordinal);
                    functionAddress = GetProcAddress(hDll, (LPCSTR)ordinal);
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)mappedImage + thunkINT->u1.AddressOfData);
                    functionAddress = GetProcAddress(hDll, (LPCSTR)importByName->Name);
                }
                
                if (functionAddress == NULL) {
                    std::cerr << "Failed to get function address. Error: " << GetLastError() << std::endl;
                    return false;
                }
                
                // Write the function address to the IAT
                thunkIAT->u1.Function = (DWORD_PTR)functionAddress;
                
                // Move to the next import
                thunkIAT++;
                thunkINT++;
            }
            
            // Move to the next import descriptor
            importDesc++;
        }
        
        return true;
    }
    
    // Set memory protections
    bool setMemoryProtections() {
        PIMAGE_SECTION_HEADER sectionHeader = peParser.getSectionHeaders();
        for (DWORD i = 0; i < peParser.getNumberOfSections(); ++i) {
            DWORD protection = PAGE_READWRITE;
            DWORD characteristics = sectionHeader[i].Characteristics;
            
            if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
                protection = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else {
                protection = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
            }
            
            void* sectionAddress = (BYTE*)mappedImage + sectionHeader[i].VirtualAddress;
            DWORD sectionSize = sectionHeader[i].Misc.VirtualSize;
            
            DWORD oldProtection;
            if (!VirtualProtect(sectionAddress, sectionSize, protection, &oldProtection)) {
                std::cerr << "Failed to set memory protection for section " << i << ". Error: " << GetLastError() << std::endl;
                return false;
            }
        }
        
        return true;
    }
    
    // Execute the loaded PE file
    bool execute() {
        if (!loaded || mappedImage == NULL) {
            std::cerr << "PE file not loaded" << std::endl;
            return false;
        }
        
        // Get the entry point
        DWORD entryPoint = peParser.getEntryPoint();
        if (entryPoint == 0) {
            std::cerr << "No entry point found" << std::endl;
            return false;
        }
        
        // Cast the entry point to a function pointer and call it
        typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);
        DllEntryProc entryProc = (DllEntryProc)((BYTE*)mappedImage + entryPoint);
        
        // Call the entry point with DLL_PROCESS_ATTACH
        BOOL result = entryProc((HINSTANCE)mappedImage, DLL_PROCESS_ATTACH, NULL);
        
        std::cout << "Entry point executed with result: " << (result ? "SUCCESS" : "FAILURE") << std::endl;
        return result != FALSE;
    }
    
    // Unload the PE file
    void unload() {
        if (loaded && mappedImage != NULL) {
            // Call the entry point with DLL_PROCESS_DETACH
            DWORD entryPoint = peParser.getEntryPoint();
            if (entryPoint != 0) {
                typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);
                DllEntryProc entryProc = (DllEntryProc)((BYTE*)mappedImage + entryPoint);
                entryProc((HINSTANCE)mappedImage, DLL_PROCESS_DETACH, NULL);
            }
            
            // Free the memory
            VirtualFree(mappedImage, 0, MEM_RELEASE);
            mappedImage = NULL;
            loaded = false;
            std::cout << "PE file unloaded" << std::endl;
        }
    }
    
    // Get the mapped image
    void* getMappedImage() const {
        return mappedImage;
    }
    
    // Check if the PE file is loaded
    bool isLoaded() const {
        return loaded;
    }
};

// Load a DLL from a file
std::vector<unsigned char> loadDllFromFile(const std::string& filePath) {
    std::vector<unsigned char> dllData;
    
    // Open the file
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return dllData;
    }
    
    // Get the file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read the file
    dllData.resize(fileSize);
    file.read((char*)dllData.data(), fileSize);
    
    return dllData;
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <dll_path>" << std::endl;
        std::cout << "Example: " << argv[0] << " C:\\path\\to\\mydll.dll" << std::endl;
        return 1;
    }
    
    std::string dllPath = argv[1];
    
    // Load the DLL from the file
    std::vector<unsigned char> dllData = loadDllFromFile(dllPath);
    if (dllData.empty()) {
        std::cerr << "Failed to load DLL from file" << std::endl;
        return 1;
    }
    
    std::cout << "Loaded " << dllData.size() << " bytes from " << dllPath << std::endl;
    
    // Create a reflective loader
    ReflectiveLoader loader(dllData);
    
    // Load the DLL into memory
    if (!loader.load()) {
        std::cerr << "Failed to load DLL into memory" << std::endl;
        return 1;
    }
    
    // Execute the DLL
    if (!loader.execute()) {
        std::cerr << "Failed to execute DLL" << std::endl;
        return 1;
    }
    
    // Keep the DLL loaded until the user presses a key
    std::cout << "DLL loaded and executed. Press Enter to unload..." << std::endl;
    std::cin.get();
    
    // Unload the DLL
    loader.unload();
    
    std::cout << "Note: This example is for educational purposes only." << std::endl;
    std::cout << "Always ensure you have proper authorization before using these techniques." << std::endl;
    
    return 0;
}

