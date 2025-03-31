/**
 * Advanced Memory Management in C - Cybersecurity Perspective
 * 
 * This program demonstrates advanced memory management techniques in C
 * with a focus on security implications and best practices.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Define a memory block structure for our custom memory pool
typedef struct MemoryBlock {
    void *memory;              // Pointer to the allocated memory
    size_t size;               // Size of the memory block
    int in_use;                // Flag to indicate if the block is in use
    struct MemoryBlock *next;  // Pointer to the next block in the list
} MemoryBlock;

// Define a memory pool structure
typedef struct {
    MemoryBlock *blocks;       // Linked list of memory blocks
    size_t total_size;         // Total size of all allocated blocks
    size_t used_size;          // Size of blocks currently in use
    int block_count;           // Number of blocks in the pool
} MemoryPool;

// Function to initialize a memory pool
MemoryPool* create_memory_pool() {
    MemoryPool *pool = (MemoryPool*)malloc(sizeof(MemoryPool));
    if (pool == NULL) {
        return NULL;
    }
    
    pool->blocks = NULL;
    pool->total_size = 0;
    pool->used_size = 0;
    pool->block_count = 0;
    
    return pool;
}

// Function to allocate memory from the pool
void* pool_alloc(MemoryPool *pool, size_t size) {
    if (pool == NULL || size == 0) {
        return NULL;
    }
    
    // First, try to find an existing free block of sufficient size
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (!current->in_use && current->size >= size) {
            // Found a suitable block
            current->in_use = 1;
            pool->used_size += current->size;
            
            // Zero out the memory for security
            memset(current->memory, 0, current->size);
            
            return current->memory;
        }
        current = current->next;
    }
    
    // No suitable block found, allocate a new one
    MemoryBlock *new_block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
    if (new_block == NULL) {
        return NULL;
    }
    
    new_block->memory = malloc(size);
    if (new_block->memory == NULL) {
        free(new_block);
        return NULL;
    }
    
    // Zero out the memory for security
    memset(new_block->memory, 0, size);
    
    new_block->size = size;
    new_block->in_use = 1;
    new_block->next = pool->blocks;
    pool->blocks = new_block;
    
    pool->total_size += size;
    pool->used_size += size;
    pool->block_count++;
    
    return new_block->memory;
}

// Function to free memory back to the pool
void pool_free(MemoryPool *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) {
        return;
    }
    
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (current->memory == ptr && current->in_use) {
            // Found the block
            current->in_use = 0;
            pool->used_size -= current->size;
            
            // Zero out the memory for security
            memset(current->memory, 0, current->size);
            
            return;
        }
        current = current->next;
    }
    
    // Pointer not found in the pool
    printf("Warning: Attempted to free a pointer not in the pool\n");
}

// Function to destroy a memory pool
void destroy_memory_pool(MemoryPool *pool) {
    if (pool == NULL) {
        return;
    }
    
    // Free all blocks
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        MemoryBlock *next = current->next;
        
        // Zero out the memory for security
        if (current->memory != NULL) {
            memset(current->memory, 0, current->size);
            free(current->memory);
        }
        
        free(current);
        current = next;
    }
    
    // Free the pool itself
    free(pool);
}

// Function to print memory pool statistics
void print_pool_stats(MemoryPool *pool) {
    if (pool == NULL) {
        printf("Pool is NULL\n");
        return;
    }
    
    printf("Memory Pool Statistics:\n");
    printf("  Total blocks: %d\n", pool->block_count);
    printf("  Total size: %zu bytes\n", pool->total_size);
    printf("  Used size: %zu bytes\n", pool->used_size);
    printf("  Free size: %zu bytes\n", pool->total_size - pool->used_size);
    
    int free_blocks = 0;
    MemoryBlock *current = pool->blocks;
    while (current != NULL) {
        if (!current->in_use) {
            free_blocks++;
        }
        current = current->next;
    }
    
    printf("  Free blocks: %d\n", free_blocks);
    printf("  Used blocks: %d\n", pool->block_count - free_blocks);
}

// Function to demonstrate memory alignment
void demonstrate_memory_alignment() {
    printf("\n=== Memory Alignment ===\n");
    
    // Define structures with different alignments
    typedef struct {
        char a;       // 1 byte
        int b;        // 4 bytes
        char c;       // 1 byte
    } Unaligned;
    
    typedef struct {
        char a;       // 1 byte
        char c;       // 1 byte
        int b;        // 4 bytes
    } BetterAligned;
    
    // Print sizes and alignments
    printf("Size of char: %zu bytes\n", sizeof(char));
    printf("Size of int: %zu bytes\n", sizeof(int));
    printf("Size of Unaligned struct: %zu bytes\n", sizeof(Unaligned));
    printf("Size of BetterAligned struct: %zu bytes\n", sizeof(BetterAligned));
    
    // Explain padding and alignment
    printf("\nMemory alignment and padding:\n");
    printf("1. The Unaligned struct has more padding due to alignment requirements\n");
    printf("2. The BetterAligned struct is more efficient in memory usage\n");
    printf("3. Proper alignment is important for performance and security\n");
    
    // Security implications
    printf("\nSecurity implications of alignment:\n");
    printf("1. Padding bytes may contain uninitialized data\n");
    printf("2. This can lead to information leakage if not properly handled\n");
    printf("3. Always initialize entire structures, not just individual fields\n");
    
    // Demonstrate alignment with malloc
    printf("\nAligned memory allocation:\n");
    
    // Standard malloc (may not be aligned for all types)
    void *ptr1 = malloc(100);
    printf("Standard malloc address: %p\n", ptr1);
    
    // Aligned allocation (C11 standard)
    void *ptr2 = NULL;
    #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    // C11 aligned_alloc
    ptr2 = aligned_alloc(16, 112);  // Allocate 112 bytes aligned to 16-byte boundary
    printf("aligned_alloc address: %p\n", ptr2);
    #else
    printf("aligned_alloc not available (requires C11)\n");
    #endif
    
    // Clean up
    free(ptr1);
    if (ptr2 != NULL) {
        free(ptr2);
    }
}

// Function to demonstrate secure memory erasure
void demonstrate_secure_memory_erasure() {
    printf("\n=== Secure Memory Erasure ===\n");
    
    // Allocate memory for sensitive data
    char *sensitive_data = (char*)malloc(100);
    if (sensitive_data == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Store sensitive data
    strcpy(sensitive_data, "Password123!@#");
    printf("Sensitive data: %s\n", sensitive_data);
    
    // Insecure way to clear memory
    printf("\nInsecure memory clearing (using free without erasure):\n");
    printf("1. Sensitive data remains in memory after free\n");
    printf("2. Could be accessed by other parts of the program or attackers\n");
    
    // Secure way to clear memory
    printf("\nSecure memory clearing:\n");
    printf("1. Overwrite memory before freeing\n");
    
    // Overwrite with zeros
    memset(sensitive_data, 0, strlen(sensitive_data));
    printf("After memset with zeros: %s\n", sensitive_data);
    
    // More secure: multiple overwrite patterns
    size_t len = 100;
    
    // First pattern: 0xFF
    memset(sensitive_data, 0xFF, len);
    
    // Second pattern: 0x00
    memset(sensitive_data, 0x00, len);
    
    // Third pattern: 0xAA
    memset(sensitive_data, 0xAA, len);
    
    // Final pattern: 0x00
    memset(sensitive_data, 0x00, len);
    
    printf("After multiple overwrites: %s\n", sensitive_data);
    
    // Free the memory
    free(sensitive_data);
    
    printf("\nSecurity best practices for sensitive data:\n");
    printf("1. Minimize the time sensitive data is kept in memory\n");
    printf("2. Use secure memory erasure before freeing\n");
    printf("3. Consider using dedicated secure memory functions\n");
    printf("4. Be aware that optimizing compilers might remove 'unnecessary' memset calls\n");
}

// Function to demonstrate memory mapping concepts
void demonstrate_memory_mapping() {
    printf("\n=== Memory Mapping Concepts ===\n");
    
    printf("Memory mapping allows direct access to files or devices through memory:\n");
    printf("1. Maps files directly into memory for efficient access\n");
    printf("2. Allows sharing memory between processes\n");
    printf("3. Useful for implementing shared memory communication\n");
    
    printf("\nIn real systems, memory mapping is implemented using:\n");
    printf("- mmap() on Unix/Linux systems\n");
    printf("- MapViewOfFile() on Windows systems\n");
    
    printf("\nSecurity implications of memory mapping:\n");
    printf("1. Mapped memory can be shared between processes\n");
    printf("2. Can lead to information leakage if not properly secured\n");
    printf("3. Memory permissions (read/write/execute) must be properly set\n");
    printf("4. Memory-mapped files persist changes to disk\n");
}

// Function to demonstrate memory protection techniques
void demonstrate_memory_protection() {
    printf("\n=== Memory Protection Techniques ===\n");
    
    printf("Modern systems use various memory protection techniques:\n");
    
    printf("\n1. Address Space Layout Randomization (ASLR):\n");
    printf("   - Randomizes memory addresses to prevent predictable exploits\n");
    printf("   - Makes it harder for attackers to locate specific memory addresses\n");
    
    printf("\n2. Data Execution Prevention (DEP):\n");
    printf("   - Marks memory regions as non-executable\n");
    printf("   - Prevents code execution from data sections\n");
    
    printf("\n3. Stack Canaries:\n");
    printf("   - Places known values on the stack to detect buffer overflows\n");
    printf("   - Program crashes if canary values are modified\n");
    
    printf("\n4. Memory Access Permissions:\n");
    printf("   - Read-only, write-only, or read-write permissions\n");
    printf("   - Execute permissions control which memory can run code\n");
    
    printf("\n5. Guard Pages:\n");
    printf("   - Special pages placed between memory regions\n");
    printf("   - Accessing these pages triggers exceptions\n");
    printf("   - Helps detect buffer overflows and underflows\n");
    
    printf("\nImplementing these protections in C programs:\n");
    printf("1. Use compiler flags like -fstack-protector for stack canaries\n");
    printf("2. Mark data as read-only when appropriate\n");
    printf("3. Avoid executable stacks with -Wl,-z,noexecstack\n");
    printf("4. Use position-independent code with -fPIC\n");
}

// Function to demonstrate custom memory allocator
void demonstrate_custom_allocator() {
    printf("\n=== Custom Memory Allocator ===\n");
    
    // Create a memory pool
    MemoryPool *pool = create_memory_pool();
    if (pool == NULL) {
        printf("Failed to create memory pool\n");
        return;
    }
    
    // Print initial pool statistics
    printf("Initial pool state:\n");
    print_pool_stats(pool);
    
    // Allocate memory from the pool
    printf("\nAllocating memory from the pool:\n");
    
    char *str1 = (char*)pool_alloc(pool, 50);
    if (str1 != NULL) {
        strcpy(str1, "This is the first string in the pool");
        printf("Allocated str1: %s\n", str1);
    }
    
    int *numbers = (int*)pool_alloc(pool, 5 * sizeof(int));
    if (numbers != NULL) {
        for (int i = 0; i < 5; i++) {
            numbers[i] = i * 10;
        }
        printf("Allocated numbers: ");
        for (int i = 0; i < 5; i++) {
            printf("%d ", numbers[i]);
        }
        printf("\n");
    }
    
    char *str2 = (char*)pool_alloc(pool, 30);
    if (str2 != NULL) {
        strcpy(str2, "Second string in the pool");
        printf("Allocated str2: %s\n", str2);
    }
    
    // Print pool statistics after allocation
    printf("\nPool state after allocation:\n");
    print_pool_stats(pool);
    
    // Free some memory
    printf("\nFreeing memory back to the pool:\n");
    pool_free(pool, str1);
    printf("Freed str1\n");
    
    // Print pool statistics after freeing
    printf("\nPool state after freeing str1:\n");
    print_pool_stats(pool);
    
    // Allocate more memory
    printf("\nAllocating more memory from the pool:\n");
    char *str3 = (char*)pool_alloc(pool, 40);
    if (str3 != NULL) {
        strcpy(str3, "This string reuses the freed memory");
        printf("Allocated str3: %s\n", str3);
    }
    
    // Print final pool statistics
    printf("\nFinal pool state:\n");
    print_pool_stats(pool);
    
    // Destroy the pool
    destroy_memory_pool(pool);
    printf("\nMemory pool destroyed\n");
    
    // Security benefits of custom allocators
    printf("\nSecurity benefits of custom memory allocators:\n");
    printf("1. Better control over memory layout and usage\n");
    printf("2. Can implement security features like guard pages\n");
    printf("3. Can zero out memory when allocating and freeing\n");
    printf("4. Can detect and prevent memory leaks\n");
    printf("5. Can implement memory access policies\n");
}

int main() {
    printf("=== Advanced Memory Management in C: Cybersecurity Perspective ===\n");
    
    // Demonstrate memory alignment
    demonstrate_memory_alignment();
    
    // Demonstrate secure memory erasure
    demonstrate_secure_memory_erasure();
    
    // Demonstrate memory mapping concepts
    demonstrate_memory_mapping();
    
    // Demonstrate memory protection techniques
    demonstrate_memory_protection();
    
    // Demonstrate custom memory allocator
    demonstrate_custom_allocator();
    
    printf("\n=== Security Best Practices for Advanced Memory Management ===\n");
    printf("1. Always initialize memory before use\n");
    printf("2. Securely erase sensitive data before freeing memory\n");
    printf("3. Be aware of memory alignment and padding\n");
    printf("4. Use memory protection features when available\n");
    printf("5. Consider custom allocators for better control\n");
    printf("6. Be cautious with shared memory\n");
    printf("7. Validate all memory operations\n");
    printf("8. Use tools like Valgrind to detect memory issues\n");
    
    return 0;
}

