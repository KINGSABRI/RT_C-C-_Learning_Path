#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>

// Red Team Focus: Heap spraying can be used to:
// 1. Increase reliability of memory corruption exploits
// 2. Prepare memory for shellcode execution
// 3. Bypass ASLR by creating predictable memory layouts

// Simulated vulnerable function with a buffer overflow
void vulnerableFunction(const char* input) {
    char buffer[16];
    // Unsafe - no bounds checking
    strcpy(buffer, input);
    std::cout << "Buffer content: " << buffer << std::endl;
}

// Heap spray demonstration class
class HeapSpray {
private:
    std::vector<void*> allocations;
    size_t blockSize;
    size_t blockCount;
    char* pattern;
    size_t patternSize;

public:
    HeapSpray(size_t size, size_t count, const char* payload, size_t payloadSize) 
        : blockSize(size), blockCount(count), patternSize(payloadSize) {
        // Create the pattern with NOP sled and payload
        pattern = new char[patternSize];
        
        // Fill with NOP equivalent (0x90 for x86)
        memset(pattern, 0x90, patternSize);
        
        // Place the payload at the end of the pattern
        if (payload && payloadSize > 0) {
            memcpy(pattern + patternSize - payloadSize, payload, payloadSize);
        }
    }
    
    ~HeapSpray() {
        // Free all allocations
        for (void* ptr : allocations) {
            free(ptr);
        }
        
        delete[] pattern;
    }
    
    // Spray the heap with the pattern
    void spray() {
        std::cout << "Spraying heap with " << blockCount << " blocks of size " << blockSize << " bytes..." << std::endl;
        
        for (size_t i = 0; i < blockCount; ++i) {
            // Allocate a block
            void* block = malloc(blockSize);
            if (!block) {
                std::cerr << "Failed to allocate block " << i << std::endl;
                continue;
            }
            
            // Fill the block with the pattern
            for (size_t offset = 0; offset < blockSize; offset += patternSize) {
                size_t bytesToCopy = std::min(patternSize, blockSize - offset);
                memcpy(static_cast<char*>(block) + offset, pattern, bytesToCopy);
            }
            
            // Save the allocation
            allocations.push_back(block);
        }
        
        std::cout << "Heap spray complete. Allocated " << allocations.size() << " blocks." << std::endl;
    }
    
    // Print statistics about the heap spray
    void printStats() {
        size_t totalMemory = allocations.size() * blockSize;
        std::cout << "Heap spray statistics:" << std::endl;
        std::cout << "  Blocks allocated: " << allocations.size() << std::endl;
        std::cout << "  Block size: " << blockSize << " bytes" << std::endl;
        std::cout << "  Total memory: " << totalMemory << " bytes (" << (totalMemory / 1024.0 / 1024.0) << " MB)" << std::endl;
        
        // Print some addresses to show the distribution
        if (!allocations.empty()) {
            std::cout << "  Sample addresses:" << std::endl;
            for (size_t i = 0; i < std::min(allocations.size(), size_t(5)); ++i) {
                std::cout << "    " << allocations[i] << std::endl;
            }
        }
    }
};

int main() {
    // Seed the random number generator
    srand(static_cast<unsigned>(time(nullptr)));
    
    // Create a simple payload (in a real exploit, this would be shellcode)
    const char* payload = "PAYLOAD";
    size_t payloadSize = strlen(payload);
    
    // Create a heap spray with 1KB blocks, 1000 blocks, and our payload
    HeapSpray heapSpray(1024, 1000, payload, payloadSize);
    
    // Spray the heap
    heapSpray.spray();
    
    // Print statistics
    heapSpray.printStats();
    
    // Demonstrate a buffer overflow (for educational purposes only)
    std::cout << "\nDemonstrating buffer overflow vulnerability:" << std::endl;
    
    // Create an input that's longer than the buffer
    char input[32];
    memset(input, 'A', sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';
    
    // Call the vulnerable function
    std::cout << "Calling vulnerable function with input of length " << strlen(input) << std::endl;
    vulnerableFunction(input);
    
    std::cout << "\nNote: This is a simplified demonstration for educational purposes." << std::endl;
    std::cout << "In a real-world scenario, the heap spray would be combined with an exploit" << std::endl;
    std::cout << "that redirects execution to the sprayed memory." << std::endl;
    
    return 0;
}

