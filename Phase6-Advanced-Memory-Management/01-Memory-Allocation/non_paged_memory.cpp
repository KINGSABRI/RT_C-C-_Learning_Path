#include <iostream>
#include <windows.h>

// Red Team Focus: Non-paged memory can be useful for:
// 1. Ensuring code is always resident in physical memory
// 2. Avoiding memory being written to disk (and potentially scanned)
// 3. Improving performance of time-critical operations

class NonPagedMemory {
private:
    void* memory;
    SIZE_T size;

public:
    NonPagedMemory(SIZE_T requestedSize) : memory(nullptr), size(0) {
        // Allocate non-paged memory
        memory = VirtualAlloc(NULL, requestedSize, MEM_COMMIT | MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
        
        if (memory) {
            size = requestedSize;
            std::cout << "Successfully allocated " << size << " bytes of non-paged memory at " << memory << std::endl;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to allocate non-paged memory. Error code: " << error << std::endl;
        }
    }
    
    ~NonPagedMemory() {
        if (memory) {
            VirtualFree(memory, 0, MEM_RELEASE);
            std::cout << "Released non-paged memory at " << memory << std::endl;
        }
    }
    
    void* getMemory() const {
        return memory;
    }
    
    SIZE_T getSize() const {
        return size;
    }
    
    bool isValid() const {
        return memory != nullptr;
    }
    
    // Lock the memory to prevent paging
    bool lockMemory() {
        if (!memory) return false;
        
        if (VirtualLock(memory, size)) {
            std::cout << "Memory locked successfully" << std::endl;
            return true;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to lock memory. Error code: " << error << std::endl;
            return false;
        }
    }
    
    // Unlock the memory
    bool unlockMemory() {
        if (!memory) return false;
        
        if (VirtualUnlock(memory, size)) {
            std::cout << "Memory unlocked successfully" << std::endl;
            return true;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to unlock memory. Error code: " << error << std::endl;
            return false;
        }
    }
    
    // Change memory protection
    bool setProtection(DWORD protection) {
        if (!memory) return false;
        
        DWORD oldProtection;
        if (VirtualProtect(memory, size, protection, &oldProtection)) {
            std::cout << "Memory protection changed from " << oldProtection << " to " << protection << std::endl;
            return true;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to change memory protection. Error code: " << error << std::endl;
            return false;
        }
    }
};

int main() {
    // Allocate 1MB of non-paged memory
    NonPagedMemory nonPagedMem(1024 * 1024);
    
    if (!nonPagedMem.isValid()) {
        std::cerr << "Failed to allocate non-paged memory" << std::endl;
        return 1;
    }
    
    // Lock the memory
    nonPagedMem.lockMemory();
    
    // Get the memory pointer
    void* mem = nonPagedMem.getMemory();
    
    // Write some data to the memory
    char* charMem = static_cast<char*>(mem);
    for (int i = 0; i < 26; ++i) {
        charMem[i] = 'A' + i;
    }
    charMem[26] = '\0';
    
    // Read the data back
    std::cout << "Data in memory: " << charMem << std::endl;
    
    // Change memory protection to execute-read
    nonPagedMem.setProtection(PAGE_EXECUTE_READ);
    
    // Unlock the memory before exiting
    nonPagedMem.unlockMemory();
    
    return 0;
}

