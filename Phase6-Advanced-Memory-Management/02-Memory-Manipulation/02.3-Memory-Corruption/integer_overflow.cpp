/**
 * @file integer_overflow.cpp
 * @brief Demonstrates integer overflow vulnerabilities and exploitation techniques
 *
 * This file demonstrates how integer overflow vulnerabilities occur and how they
 * can be exploited. It includes examples of vulnerable code, exploitation techniques,
 * and mitigation strategies. Integer overflows occur when arithmetic operations
 * produce results that exceed the maximum value representable by the integer type.
 *
 * WARNING: This code intentionally contains vulnerabilities for educational purposes.
 * Do not use these techniques on systems without proper authorization.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 integer_overflow.cpp -o integer_overflow.exe
 *
 * Red Team Applications:
 * - Exploiting vulnerable applications to bypass security checks
 * - Triggering buffer overflows through integer overflows
 * - Understanding memory corruption vulnerabilities
 * - Developing custom exploits for penetration testing
 */

#include <iostream>
#include <cstring>
#include <climits>
#include <vector>

// Function prototypes
void demonstrate_integer_overflow_basics();
void demonstrate_integer_overflow_allocation();
void demonstrate_integer_overflow_loop();
void demonstrate_integer_overflow_array();
void demonstrate_mitigation();

/**
 * @brief Main function that demonstrates different aspects of integer overflow vulnerabilities
 */
int main()
{
    std::cout << "=== Integer Overflow Vulnerability Demonstration ===" << std::endl;
    std::cout << std::endl;

    // Demonstrate integer overflow basics
    std::cout << "1. Integer Overflow Basics:" << std::endl;
    demonstrate_integer_overflow_basics();
    std::cout << std::endl;

    // Demonstrate integer overflow in memory allocation
    std::cout << "2. Integer Overflow in Memory Allocation:" << std::endl;
    demonstrate_integer_overflow_allocation();
    std::cout << std::endl;

    // Demonstrate integer overflow in loops
    std::cout << "3. Integer Overflow in Loops:" << std::endl;
    demonstrate_integer_overflow_loop();
    std::cout << std::endl;

    // Demonstrate integer overflow in array indexing
    std::cout << "4. Integer Overflow in Array Indexing:" << std::endl;
    demonstrate_integer_overflow_array();
    std::cout << std::endl;

    // Demonstrate mitigation techniques
    std::cout << "5. Mitigation Techniques:" << std::endl;
    demonstrate_mitigation();

    return 0;
}

/**
 * @brief Demonstrates the basics of integer overflow
 */
void demonstrate_integer_overflow_basics()
{
    std::cout << "Integer overflow occurs when an arithmetic operation produces a result" << std::endl;
    std::cout << "that exceeds the maximum value representable by the integer type." << std::endl;
    std::cout << std::endl;

    // Demonstrate unsigned integer overflow
    std::cout << "Unsigned integer overflow:" << std::endl;
    unsigned int max_uint = UINT_MAX;
    std::cout << "Maximum unsigned int value: " << max_uint << std::endl;
    std::cout << "Maximum + 1: " << max_uint + 1 << std::endl;
    std::cout << "This wraps around to 0" << std::endl;

    std::cout << std::endl;

    // Demonstrate signed integer overflow
    std::cout << "Signed integer overflow:" << std::endl;
    int max_int = INT_MAX;
    std::cout << "Maximum signed int value: " << max_int << std::endl;
    std::cout << "Maximum + 1: " << max_int + 1 << std::endl;
    std::cout << "This wraps around to INT_MIN (negative)" << std::endl;

    std::cout << std::endl;

    // Demonstrate signed integer underflow
    std::cout << "Signed integer underflow:" << std::endl;
    int min_int = INT_MIN;
    std::cout << "Minimum signed int value: " << min_int << std::endl;
    std::cout << "Minimum - 1: " << min_int - 1 << std::endl;
    std::cout << "This wraps around to INT_MAX (positive)" << std::endl;

    std::cout << std::endl;

    // Demonstrate multiplication overflow
    std::cout << "Multiplication overflow:" << std::endl;
    int large_value = 1000000;
    std::cout << "large_value: " << large_value << std::endl;
    std::cout << "large_value * large_value: " << large_value * large_value << std::endl;
    std::cout << "The result exceeds INT_MAX and overflows" << std::endl;

    std::cout << std::endl;
    std::cout << "Integer overflow is undefined behavior for signed integers in C/C++," << std::endl;
    std::cout << "but it wraps around for unsigned integers." << std::endl;
}

/**
 * @brief A vulnerable function that contains an integer overflow in memory allocation
 *
 * @param num_elements Number of elements to allocate
 * @param element_size Size of each element
 * @return void* Pointer to the allocated memory, or nullptr on failure
 */
void *vulnerable_allocate(size_t num_elements, size_t element_size)
{
    // Vulnerable: No overflow check
    size_t total_size = num_elements * element_size;

    // Allocate memory
    void *buffer = malloc(total_size);

    return buffer;
}

/**
 * @brief Demonstrates integer overflow in memory allocation
 */
void demonstrate_integer_overflow_allocation()
{
    std::cout << "Integer overflow can lead to insufficient memory allocation:" << std::endl;

    // Safe allocation
    size_t num_elements = 10;
    size_t element_size = 4;

    std::cout << "Safe allocation:" << std::endl;
    std::cout << "num_elements: " << num_elements << std::endl;
    std::cout << "element_size: " << element_size << std::endl;
    std::cout << "total_size: " << num_elements * element_size << std::endl;

    void *safe_buffer = vulnerable_allocate(num_elements, element_size);
    if (safe_buffer)
    {
        std::cout << "Allocation succeeded" << std::endl;
        free(safe_buffer);
    }
    else
    {
        std::cout << "Allocation failed" << std::endl;
    }

    std::cout << std::endl;

    // Vulnerable allocation with integer overflow
    size_t large_num = SIZE_MAX / 2 + 1;
    size_t large_size = 2;

    std::cout << "Vulnerable allocation with integer overflow:" << std::endl;
    std::cout << "large_num: " << large_num << std::endl;
    std::cout << "large_size: " << large_size << std::endl;
    std::cout << "large_num * large_size (expected): " << large_num * large_size << std::endl;
    std::cout << "But due to overflow, the actual allocation size will be much smaller" << std::endl;

    void *vuln_buffer = vulnerable_allocate(large_num, large_size);
    if (vuln_buffer)
    {
        std::cout << "Allocation succeeded, but with insufficient memory" << std::endl;
        free(vuln_buffer);
    }
    else
    {
        std::cout << "Allocation failed" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker would cause an integer overflow in the size calculation" << std::endl;
    std::cout << "2. This would result in a smaller allocation than intended" << std::endl;
    std::cout << "3. When data is copied to this buffer, it would overflow" << std::endl;
    std::cout << "4. This could lead to memory corruption and potentially code execution" << std::endl;
}

/**
 * @brief Demonstrates integer overflow in loops
 */
void demonstrate_integer_overflow_loop()
{
    std::cout << "Integer overflow can lead to infinite loops:" << std::endl;

    // Safe loop
    std::cout << "Safe loop:" << std::endl;
    for (int i = 0; i < 5; i++)
    {
        std::cout << "i = " << i << std::endl;
    }

    std::cout << std::endl;

    // Vulnerable loop with potential integer overflow
    // Note: This is commented out to prevent an actual infinite loop
    std::cout << "Vulnerable loop (commented out to prevent infinite loop):" << std::endl;
    std::cout << "for (int i = 0; i < 5; i += 2147483647) {" << std::endl;
    std::cout << "    // This loop would never terminate due to integer overflow" << std::endl;
    std::cout << "}" << std::endl;

    std::cout << std::endl;
    std::cout << "Explanation:" << std::endl;
    std::cout << "1. If i is incremented by a value close to INT_MAX" << std::endl;
    std::cout << "2. The addition would overflow and i would remain small" << std::endl;
    std::cout << "3. The loop condition (i < 5) would always be true" << std::endl;
    std::cout << "4. This would result in an infinite loop" << std::endl;

    // Another example with unsigned integers
    std::cout << std::endl;
    std::cout << "Another vulnerable pattern (decreasing unsigned integer):" << std::endl;
    std::cout << "for (unsigned int i = 10; i >= 0; i--) {" << std::endl;
    std::cout << "    // When i becomes 0 and decrements, it wraps around to UINT_MAX" << std::endl;
    std::cout << "    // The condition (i >= 0) is always true for unsigned integers" << std::endl;
    std::cout << "}" << std::endl;

    std::cout << std::endl;
    std::cout << "Correct version:" << std::endl;
    std::cout << "for (unsigned int i = 10; i != UINT_MAX; i--) {" << std::endl;
    std::cout << "    // This loop will terminate correctly" << std::endl;
    std::cout << "}" << std::endl;
}

/**
 * @brief A vulnerable function that contains an integer overflow in array indexing
 *
 * @param index The index to access
 * @param offset The offset to add to the index
 * @param arr The array to access
 * @param arr_size The size of the array
 * @return int The value at the calculated index
 */
int vulnerable_array_access(int index, int offset, const int *arr, size_t arr_size)
{
    // Vulnerable: No overflow check
    int actual_index = index + offset;

    // Bounds check
    if (actual_index >= 0 && static_cast<size_t>(actual_index) < arr_size)
    {
        return arr[actual_index];
    }
    else
    {
        std::cout << "Index out of bounds" << std::endl;
        return -1;
    }
}

/**
 * @brief Demonstrates integer overflow in array indexing
 */
void demonstrate_integer_overflow_array()
{
    std::cout << "Integer overflow can lead to array index out of bounds:" << std::endl;

    // Create an array
    const int arr_size = 10;
    int arr[arr_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // Safe access
    int index = 5;
    int offset = 2;

    std::cout << "Safe access:" << std::endl;
    std::cout << "index: " << index << std::endl;
    std::cout << "offset: " << offset << std::endl;
    std::cout << "index + offset: " << index + offset << std::endl;

    int value = vulnerable_array_access(index, offset, arr, arr_size);
    std::cout << "Value at index " << index + offset << ": " << value << std::endl;

    std::cout << std::endl;

    // Vulnerable access with integer overflow
    index = INT_MAX;
    offset = 1;

    std::cout << "Vulnerable access with integer overflow:" << std::endl;
    std::cout << "index: " << index << std::endl;
    std::cout << "offset: " << offset << std::endl;
    std::cout << "index + offset (expected): " << static_cast<long long>(index) + offset << std::endl;
    std::cout << "But due to overflow, the actual index will be: " << index + offset << std::endl;

    value = vulnerable_array_access(index, offset, arr, arr_size);

    std::cout << std::endl;
    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker would cause an integer overflow in the index calculation" << std::endl;
    std::cout << "2. This could bypass bounds checks that don't account for overflow" << std::endl;
    std::cout << "3. The attacker could then access memory outside the intended array" << std::endl;
    std::cout << "4. This could lead to information disclosure or memory corruption" << std::endl;
}

/**
 * @brief A safer version of the allocation function with overflow checking
 *
 * @param num_elements Number of elements to allocate
 * @param element_size Size of each element
 * @return void* Pointer to the allocated memory, or nullptr on failure
 */
void *safe_allocate(size_t num_elements, size_t element_size)
{
    // Check for overflow in the multiplication
    if (num_elements > 0 && SIZE_MAX / num_elements < element_size)
    {
        std::cout << "Integer overflow detected in size calculation" << std::endl;
        return nullptr;
    }

    // Safe to multiply now
    size_t total_size = num_elements * element_size;

    // Allocate memory
    void *buffer = malloc(total_size);

    return buffer;
}

/**
 * @brief A safer version of the array access function with overflow checking
 *
 * @param index The index to access
 * @param offset The offset to add to the index
 * @param arr The array to access
 * @param arr_size The size of the array
 * @return int The value at the calculated index
 */
int safe_array_access(int index, int offset, const int *arr, size_t arr_size)
{
    // Check for overflow in the addition
    if ((offset > 0 && index > INT_MAX - offset) ||
        (offset < 0 && index < INT_MIN - offset))
    {
        std::cout << "Integer overflow detected in index calculation" << std::endl;
        return -1;
    }

    // Safe to add now
    int actual_index = index + offset;

    // Bounds check
    if (actual_index >= 0 && static_cast<size_t>(actual_index) < arr_size)
    {
        return arr[actual_index];
    }
    else
    {
        std::cout << "Index out of bounds" << std::endl;
        return -1;
    }
}

/**
 * @brief Demonstrates mitigation techniques for integer overflow vulnerabilities
 */
void demonstrate_mitigation()
{
    std::cout << "1. Check for overflow before performing arithmetic operations:" << std::endl;

    // Demonstrate safe allocation
    size_t large_num = SIZE_MAX / 2 + 1;
    size_t large_size = 2;

    std::cout << "Safe allocation with overflow checking:" << std::endl;
    std::cout << "large_num: " << large_num << std::endl;
    std::cout << "large_size: " << large_size << std::endl;

    void *safe_buffer = safe_allocate(large_num, large_size);
    if (safe_buffer)
    {
        std::cout << "Allocation succeeded" << std::endl;
        free(safe_buffer);
    }
    else
    {
        std::cout << "Allocation failed due to overflow check" << std::endl;
    }

    std::cout << std::endl;

    // Demonstrate safe array access
    const int arr_size = 10;
    int arr[arr_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    int index = INT_MAX;
    int offset = 1;

    std::cout << "Safe array access with overflow checking:" << std::endl;
    std::cout << "index: " << index << std::endl;
    std::cout << "offset: " << offset << std::endl;

    int value = safe_array_access(index, offset, arr, arr_size);

    std::cout << std::endl;
    std::cout << "2. Use wider integer types for intermediate calculations:" << std::endl;
    std::cout << "   - Use int64_t or uint64_t for calculations that might overflow 32-bit integers" << std::endl;
    std::cout << "   - Example: int64_t total = static_cast<int64_t>(a) + b;" << std::endl;

    std::cout << std::endl;
    std::cout << "3. Use safe integer libraries:" << std::endl;
    std::cout << "   - SafeInt: https://github.com/dcleblanc/SafeInt" << std::endl;
    std::cout << "   - IntegerLib: Part of the Microsoft Security Development Lifecycle" << std::endl;

    std::cout << std::endl;
    std::cout << "4. Use compiler flags and features:" << std::endl;
    std::cout << "   - GCC/Clang: -ftrapv (trap on signed integer overflow)" << std::endl;
    std::cout << "   - MSVC: /sdl (additional security checks)" << std::endl;
    std::cout << "   - C++20: std::safe_numerics (proposed)" << std::endl;

    std::cout << std::endl;
    std::cout << "5. Use saturating arithmetic when appropriate:" << std::endl;
    std::cout << "   - Clamp results to min/max values instead of wrapping" << std::endl;
    std::cout << "   - Example:" << std::endl;
    std::cout << "     if (a > INT_MAX - b) {" << std::endl;
    std::cout << "         result = INT_MAX;" << std::endl;
    std::cout << "     } else {" << std::endl;
    std::cout << "         result = a + b;" << std::endl;
    std::cout << "     }" << std::endl;

    std::cout << std::endl;
    std::cout << "6. Use size_t for sizes and indices, but be aware of its limitations:" << std::endl;
    std::cout << "   - size_t is unsigned, so it can't represent negative values" << std::endl;
    std::cout << "   - Subtraction can still underflow" << std::endl;

    std::cout << std::endl;
    std::cout << "7. Be careful with type conversions:" << std::endl;
    std::cout << "   - Implicit conversions can lead to unexpected results" << std::endl;
    std::cout << "   - Use explicit casts and check for overflow" << std::endl;
}
