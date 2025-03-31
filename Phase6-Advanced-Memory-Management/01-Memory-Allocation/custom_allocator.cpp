#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>

// Custom memory allocator class
class CustomAllocator {
private:
    struct MemoryBlock {
        void* address;
        size_t size;
        bool used;
    };
    
    std::vector<MemoryBlock> blocks;
    void* memory_pool;
    size_t pool_size;
    size_t used_memory;

public:
    CustomAllocator(size_t size) : pool_size(size), used_memory(0) {
        // Allocate a large memory pool
        memory_pool = malloc(size);
        if (!memory_pool) {
            throw std::bad_alloc();
        }
        
        // Initialize the memory pool with zeros
        memset(memory_pool, 0, size);
        
        // Add the entire pool as a free block
        blocks.push_back({memory_pool, size, false});
    }
    
    ~CustomAllocator() {
        // Free the memory pool
        free(memory_pool);
    }
    
    void* allocate(size_t size) {
        // Find a free block that's large enough
        for (auto& block : blocks) {
            if (!block.used && block.size >= size) {
                // Mark this block as used
                block.used = true;
                
                // If the block is larger than needed, split it
                if (block.size > size + sizeof(MemoryBlock)) {
                    MemoryBlock new_block;
                    new_block.address = static_cast<char*>(block.address) + size;
                    new_block.size = block.size - size;
                    new_block.used = false;
                    
                    block.size = size;
                    blocks.push_back(new_block);
                }
                
                used_memory += block.size;
                return block.address;
            }
        }
        
        // No suitable block found
        throw std::bad_alloc();
    }
    
    void deallocate(void* ptr) {
        // Find the block
        for (auto& block : blocks) {
            if (block.address == ptr) {
                block.used = false;
                used_memory -= block.size;
                
                // Try to merge with adjacent free blocks
                mergeBlocks();
                return;
            }
        }
        
        // Block not found
        throw std::invalid_argument("Invalid pointer");
    }
    
    void mergeBlocks() {
        // Sort blocks by address
        std::sort(blocks.begin(), blocks.end(), 
                 [](const MemoryBlock& a, const MemoryBlock& b) {
                     return a.address < b.address;
                 });
        
        // Merge adjacent free blocks
        for (size_t i = 0; i < blocks.size() - 1; ++i) {
            if (!blocks[i].used && !blocks[i + 1].used) {
                // Merge the blocks
                blocks[i].size += blocks[i + 1].size;
                blocks.erase(blocks.begin() + i + 1);
                --i; // Check this position again
            }
        }
    }
    
    void printStatus() {
        std::cout << "Memory pool status:" << std::endl;
        std::cout << "Total size: " << pool_size << " bytes" << std::endl;
        std::cout << "Used memory: " << used_memory << " bytes" << std::endl;
        std::cout << "Free memory: " << pool_size - used_memory << " bytes" << std::endl;
        std::cout << "Blocks: " << blocks.size() << std::endl;
        
        for (size_t i = 0; i < blocks.size(); ++i) {
            std::cout << "Block " << i << ": "
                      << "Address: " << blocks[i].address
                      << ", Size: " << blocks[i].size
                      << ", Status: " << (blocks[i].used ? "Used" : "Free")
                      << std::endl;
        }
    }
};

// Red Team Focus: Memory allocation techniques can be used to:
// 1. Hide malicious code in memory
// 2. Evade memory scanning by AV/EDR
// 3. Create execution space for shellcode

int main() {
    try {
        // Create a custom allocator with a 1MB memory pool
        CustomAllocator allocator(1024 * 1024);
        
        // Allocate some memory
        void* ptr1 = allocator.allocate(1024);
        void* ptr2 = allocator.allocate(2048);
        void* ptr3 = allocator.allocate(4096);
        
        // Print the status
        allocator.printStatus();
        
        // Free some memory
        allocator.deallocate(ptr2);
        
        // Print the status again
        std::cout << "\nAfter freeing ptr2:" << std::endl;
        allocator.printStatus();
        
        // Allocate more memory
        void* ptr4 = allocator.allocate(1500);
        
        // Print the status again
        std::cout << "\nAfter allocating ptr4:" << std::endl;
        allocator.printStatus();
        
        // Free all memory
        allocator.deallocate(ptr1);
        allocator.deallocate(ptr3);
        allocator.deallocate(ptr4);
        
        // Print the final status
        std::cout << "\nFinal status:" << std::endl;
        allocator.printStatus();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

