/**
 * @file heap_overflow.cpp
 * @brief Demonstrates heap overflow vulnerabilities and exploitation techniques
 *
 * This file demonstrates how heap overflows occur and how they can be
 * exploited. It includes examples of vulnerable code, exploitation techniques,
 * and mitigation strategies. Heap overflows occur when data is written beyond
 * the bounds of a dynamically allocated buffer on the heap.
 *
 * WARNING: This code intentionally contains vulnerabilities for educational purposes.
 * Do not use these techniques on systems without proper authorization.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 heap_overflow.cpp -o heap_overflow.exe
 *
 * Red Team Applications:
 * - Exploiting vulnerable applications to gain code execution
 * - Corrupting heap metadata to manipulate program flow
 * - Understanding memory corruption vulnerabilities
 * - Developing custom exploits for penetration testing
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <vector>

// Structure to demonstrate heap metadata corruption
struct HeapBlock
{
    size_t size;
    HeapBlock *next;
    HeapBlock *prev;
    bool is_free;
    char data[1]; // Flexible array member
};

// Function prototypes
void demonstrate_heap_layout();
void demonstrate_heap_overflow();
void demonstrate_use_after_free();
void demonstrate_double_free();
void demonstrate_mitigation();
void print_memory(const void *addr, size_t len);

/**
 * @brief Main function that demonstrates different aspects of heap overflows
 */
int main()
{
    std::cout << "=== Heap Overflow Demonstration ===" << std::endl;
    std::cout << std::endl;

    // Demonstrate the heap layout
    std::cout << "1. Demonstrating Heap Layout:" << std::endl;
    demonstrate_heap_layout();
    std::cout << std::endl;

    // Demonstrate a heap overflow
    std::cout << "2. Demonstrating Heap Overflow:" << std::endl;
    demonstrate_heap_overflow();
    std::cout << std::endl;

    // Demonstrate use-after-free
    std::cout << "3. Demonstrating Use-After-Free:" << std::endl;
    demonstrate_use_after_free();
    std::cout << std::endl;

    // Demonstrate double free
    std::cout << "4. Demonstrating Double Free:" << std::endl;
    demonstrate_double_free();
    std::cout << std::endl;

    // Demonstrate mitigation techniques
    std::cout << "5. Demonstrating Mitigation Techniques:" << std::endl;
    demonstrate_mitigation();

    return 0;
}

/**
 * @brief A vulnerable function that contains a heap overflow vulnerability
 *
 * @param input The input string to copy into the buffer
 * @return char* Pointer to the allocated buffer
 */
char *vulnerable_heap_function(const char *input)
{
    // Allocate a small buffer on the heap
    char *buffer = new char[16];

    // Vulnerable: No bounds checking
    strcpy(buffer, input);

    return buffer;
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

    std::cout << std::dec; // Reset to decimal
}

/**
 * @brief Demonstrates the layout of the heap
 *
 * This function shows how dynamically allocated memory is arranged on the heap
 * and how heap metadata is structured.
 */
void demonstrate_heap_layout()
{
    // Allocate memory on the heap
    int *a = new int(0x41414141);
    int *b = new int(0x42424242);
    char *buffer = new char[16];
    strcpy(buffer, "BUFFER");
    int *c = new int(0x43434343);

    // Print the addresses of the allocations
    std::cout << "Address of a: " << a << " (value: 0x" << std::hex << *a << ")" << std::dec << std::endl;
    std::cout << "Address of b: " << b << " (value: 0x" << std::hex << *b << ")" << std::dec << std::endl;
    std::cout << "Address of buffer: " << static_cast<void *>(buffer) << " (content: " << buffer << ")" << std::endl;
    std::cout << "Address of c: " << c << " (value: 0x" << std::hex << *c << ")" << std::dec << std::endl;

    // Print the heap memory
    std::cout << "Heap memory around buffer:" << std::endl;
    print_memory(buffer - 16, 64); // Print a region of the heap

    std::cout << "Note how allocations are arranged on the heap:" << std::endl;
    std::cout << "- Each allocation is preceded by heap metadata" << std::endl;
    std::cout << "- Metadata includes size, flags, and possibly pointers to adjacent blocks" << std::endl;
    std::cout << "- Heap overflows can corrupt this metadata" << std::endl;
    std::cout << "- The exact layout depends on the heap implementation (e.g., dlmalloc, jemalloc, tcmalloc)" << std::endl;

    // Clean up
    delete a;
    delete b;
    delete[] buffer;
    delete c;
}

/**
 * @brief Demonstrates a heap overflow vulnerability
 *
 * This function shows how a heap overflow can corrupt adjacent memory
 * and potentially lead to control flow hijacking.
 */
void demonstrate_heap_overflow()
{
    // Allocate two adjacent buffers
    char *buffer1 = new char[16];
    char *buffer2 = new char[16];

    // Initialize the buffers
    strcpy(buffer1, "Buffer 1");
    strcpy(buffer2, "Buffer 2");

    std::cout << "Before overflow:" << std::endl;
    std::cout << "buffer1 at " << static_cast<void *>(buffer1) << ": " << buffer1 << std::endl;
    std::cout << "buffer2 at " << static_cast<void *>(buffer2) << ": " << buffer2 << std::endl;

    // Overflow buffer1 into buffer2
    std::cout << "Overflowing buffer1..." << std::endl;
    strcpy(buffer1, "This is a very long string that will overflow into buffer2");

    std::cout << "After overflow:" << std::endl;
    std::cout << "buffer1 at " << static_cast<void *>(buffer1) << ": " << buffer1 << std::endl;
    std::cout << "buffer2 at " << static_cast<void *>(buffer2) << ": " << buffer2 << std::endl;

    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. The overflow could corrupt heap metadata" << std::endl;
    std::cout << "2. This could lead to arbitrary memory writes during subsequent allocations/frees" << std::endl;
    std::cout << "3. Ultimately, this could allow an attacker to hijack control flow" << std::endl;

    // Clean up
    delete[] buffer1;
    delete[] buffer2;
}

/**
 * @brief Demonstrates a use-after-free vulnerability
 *
 * This function shows how using memory after it has been freed
 * can lead to security vulnerabilities.
 */
void demonstrate_use_after_free()
{
    // Allocate a buffer
    char *buffer = new char[16];

    // Initialize the buffer
    strcpy(buffer, "Original data");

    std::cout << "Original buffer at " << static_cast<void *>(buffer) << ": " << buffer << std::endl;

    // Free the buffer
    std::cout << "Freeing the buffer..." << std::endl;
    delete[] buffer;

    // Use after free (dangerous!)
    std::cout << "Use-after-free (undefined behavior):" << std::endl;
    std::cout << "buffer still contains: " << buffer << std::endl;

    // Allocate a new buffer that might reuse the same memory
    char *new_buffer = new char[16];
    strcpy(new_buffer, "New data");

    std::cout << "New buffer at " << static_cast<void *>(new_buffer) << ": " << new_buffer << std::endl;

    // The original pointer might now point to the new data
    std::cout << "Original buffer now contains: " << buffer << std::endl;

    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker could allocate memory after the free" << std::endl;
    std::cout << "2. This new allocation could contain attacker-controlled data" << std::endl;
    std::cout << "3. When the dangling pointer is used, it operates on the attacker's data" << std::endl;
    std::cout << "4. This could lead to information disclosure or control flow hijacking" << std::endl;

    // Clean up
    delete[] new_buffer;
    // Don't delete buffer again - it's already been freed
}

/**
 * @brief Demonstrates a double free vulnerability
 *
 * This function shows how freeing the same memory twice
 * can corrupt heap metadata and lead to security vulnerabilities.
 */
void demonstrate_double_free()
{
    // Allocate a buffer
    char *buffer = new char[16];

    // Initialize the buffer
    strcpy(buffer, "Test data");

    std::cout << "Buffer at " << static_cast<void *>(buffer) << ": " << buffer << std::endl;

    // Free the buffer
    std::cout << "Freeing the buffer once..." << std::endl;
    delete[] buffer;

    // Double free (dangerous!)
    std::cout << "Attempting to free the buffer again (double free)..." << std::endl;
    try
    {
        delete[] buffer; // This might crash or cause undefined behavior
    }
    catch (...)
    {
        std::cout << "Exception caught! The program crashed due to double free." << std::endl;
    }

    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. A double free can corrupt the heap's free list" << std::endl;
    std::cout << "2. This can cause the same memory chunk to appear twice in the free list" << std::endl;
    std::cout << "3. Subsequent allocations can return the same chunk multiple times" << std::endl;
    std::cout << "4. This can lead to overlapping allocations and memory corruption" << std::endl;
    std::cout << "5. Ultimately, this could allow an attacker to achieve arbitrary memory writes" << std::endl;
}

/**
 * @brief A safer version of the vulnerable function with bounds checking
 *
 * @param input The input string to copy into the buffer
 * @return char* Pointer to the allocated buffer
 */
char *safer_heap_function(const char *input)
{
    // Calculate the required buffer size
    size_t input_length = strlen(input);

    // Allocate a buffer of the appropriate size
    char *buffer = new char[input_length + 1]; // +1 for null terminator

    // Safe: Copy with the correct size
    strcpy(buffer, input);

    return buffer;
}

/**
 * @brief Demonstrates mitigation techniques for heap vulnerabilities
 */
void demonstrate_mitigation()
{
    // Using safer functions
    std::cout << "Using safer allocation with appropriate size:" << std::endl;
    char *buffer = safer_heap_function("This is a very long input string that will be handled safely");
    std::cout << "Buffer content: " << buffer << std::endl;
    delete[] buffer;

    std::cout << std::endl;
    std::cout << "Other mitigation techniques include:" << std::endl;
    std::cout << "1. Heap canaries: Special values placed between allocations" << std::endl;
    std::cout << "2. Heap metadata protection: Checksums or encryption of metadata" << std::endl;
    std::cout << "3. Address Space Layout Randomization (ASLR)" << std::endl;
    std::cout << "4. Use of smart pointers in C++ to prevent use-after-free and double free:" << std::endl;

    // Demonstrate smart pointers
    std::cout << "   - Using std::unique_ptr:" << std::endl;
    {
        std::unique_ptr<char[]> safe_buffer(new char[16]);
        strcpy(safe_buffer.get(), "Safe data");
        std::cout << "     safe_buffer: " << safe_buffer.get() << std::endl;
        // No need to delete - automatically freed when out of scope
    }

    std::cout << "   - Using std::shared_ptr:" << std::endl;
    {
        std::shared_ptr<char[]> shared_buffer(new char[16], std::default_delete<char[]>());
        strcpy(shared_buffer.get(), "Shared data");
        std::cout << "     shared_buffer: " << shared_buffer.get() << std::endl;

        // Create another pointer to the same memory
        std::shared_ptr<char[]> another_pointer = shared_buffer;
        std::cout << "     another_pointer: " << another_pointer.get() << std::endl;

        // Memory is only freed when all shared_ptrs are destroyed
    }

    std::cout << "5. Bounds checking containers like std::vector and std::string" << std::endl;
    std::cout << "6. Custom memory allocators with security features" << std::endl;
    std::cout << "7. Regular security testing and code reviews" << std::endl;
}
