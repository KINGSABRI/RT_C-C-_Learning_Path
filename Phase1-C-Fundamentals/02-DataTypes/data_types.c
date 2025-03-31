/**
 * Data Types in C - Cybersecurity Perspective
 * 
 * This program demonstrates various data types in C and their
 * security implications, including size, range, and memory representation.
 * 
 * Compile with: 
 * gcc data_types.c -o data_types.exe -Wno-overflow
 */

#include <stdio.h>
#include <limits.h>
#include <float.h>
#include <stdint.h>  // For fixed-width integer types

// Function to print the binary representation of an integer
void printBinary(int num) {
    // Create a mask for the most significant bit
    int mask = 1 << (sizeof(int) * 8 - 1);
    
    // Print each bit
    for (int i = 0; i < sizeof(int) * 8; i++) {
        // Print a space every 8 bits for readability
        if (i > 0 && i % 8 == 0) {
            printf(" ");
        }
        
        // Print 1 if the bit is set, 0 otherwise
        printf("%d", (num & mask) ? 1 : 0);
        
        // Shift the mask to the right
        mask >>= 1;
    }
    printf("\n");
}

int main() {
    printf("=== Data Types in C: Cybersecurity Perspective ===\n\n");
    
    // Integer types
    printf("=== Integer Types ===\n");
    printf("Size of char: %zu bytes (Range: %d to %d)\n", 
           sizeof(char), CHAR_MIN, CHAR_MAX);
    printf("Size of unsigned char: %zu bytes (Range: 0 to %d)\n", 
           sizeof(unsigned char), UCHAR_MAX);
    printf("Size of short: %zu bytes (Range: %d to %d)\n", 
           sizeof(short), SHRT_MIN, SHRT_MAX);
    printf("Size of unsigned short: %zu bytes (Range: 0 to %d)\n", 
           sizeof(unsigned short), USHRT_MAX);
    printf("Size of int: %zu bytes (Range: %d to %d)\n", 
           sizeof(int), INT_MIN, INT_MAX);
    printf("Size of unsigned int: %zu bytes (Range: 0 to %u)\n", 
           sizeof(unsigned int), UINT_MAX);
    printf("Size of long: %zu bytes (Range: %ld to %ld)\n", 
           sizeof(long), LONG_MIN, LONG_MAX);
    printf("Size of unsigned long: %zu bytes (Range: 0 to %lu)\n", 
           sizeof(unsigned long), ULONG_MAX);
    
    // Fixed-width integer types
    printf("\n=== Fixed-width Integer Types ===\n");
    printf("Size of int8_t: %zu bytes (Range: %d to %d)\n", 
           sizeof(int8_t), INT8_MIN, INT8_MAX);
    printf("Size of uint8_t: %zu bytes (Range: 0 to %u)\n", 
           sizeof(uint8_t), UINT8_MAX);
    printf("Size of int16_t: %zu bytes (Range: %d to %d)\n", 
           sizeof(int16_t), INT16_MIN, INT16_MAX);
    printf("Size of uint16_t: %zu bytes (Range: 0 to %u)\n", 
           sizeof(uint16_t), UINT16_MAX);
    printf("Size of int32_t: %zu bytes (Range: %d to %d)\n", 
           sizeof(int32_t), INT32_MIN, INT32_MAX);
    printf("Size of uint32_t: %zu bytes (Range: 0 to %u)\n", 
           sizeof(uint32_t), UINT32_MAX);
    printf("Size of int64_t: %zu bytes (Range: %lld to %lld)\n", 
           sizeof(int64_t), INT64_MIN, INT64_MAX);
    printf("Size of uint64_t: %zu bytes (Range: 0 to %llu)\n", 
           sizeof(uint64_t), UINT64_MAX);
    
    // Floating-point types
    printf("\n=== Floating-point Types ===\n");
    printf("Size of float: %zu bytes (Range: %e to %e)\n", 
           sizeof(float), FLT_MIN, FLT_MAX);
    printf("Size of double: %zu bytes (Range: %e to %e)\n", 
           sizeof(double), DBL_MIN, DBL_MAX);
    
    // Pointer types
    printf("\n=== Pointer Types ===\n");
    printf("Size of pointer: %zu bytes\n", sizeof(void*));
    
    // Security implications
    printf("\n=== Security Implications ===\n");
    
    // Integer overflow
    printf("\n1. Integer Overflow:\n");
    int max_int = INT_MAX;
    printf("   Maximum int value: %d\n", max_int);
    printf("   Maximum int + 1: %d\n", max_int + 1);  // Overflow!
    printf("   Binary representation of INT_MAX: ");
    printBinary(INT_MAX);
    printf("   Binary representation of INT_MAX + 1: ");
    printBinary(INT_MAX + 1);
    
    // Integer underflow
    printf("\n2. Integer Underflow:\n");
    int min_int = INT_MIN;
    printf("   Minimum int value: %d\n", min_int);
    printf("   Minimum int - 1: %d\n", min_int - 1);  // Underflow!
    printf("   Binary representation of INT_MIN: ");
    printBinary(INT_MIN);
    printf("   Binary representation of INT_MIN - 1: ");
    printBinary(INT_MIN - 1);
    
    // Type conversion issues
    printf("\n3. Type Conversion Issues:\n");
    unsigned int ui = 0;
    int i = -1;
    printf("   Unsigned int (0) > int (-1)? %s\n", 
           (ui > i) ? "Yes" : "No");  // Unexpected result!
    printf("   Explanation: When comparing signed and unsigned types,\n");
    printf("   the signed value is converted to unsigned, making -1\n");
    printf("   a very large positive number.\n");
    
    // Size mismatch
    printf("\n4. Size Mismatch:\n");
    int32_t large_value = 100000;
    int16_t small_container = large_value;  // Truncation!
    printf("   Original value (int32_t): %d\n", large_value);
    printf("   Truncated value (int16_t): %d\n", small_container);
    
    // Floating-point precision
    printf("\n5. Floating-point Precision:\n");
    float f = 0.1f + 0.2f;
    printf("   0.1 + 0.2 = %.20f (not exactly 0.3!)\n", f);
    printf("   This can cause issues in financial calculations\n");
    printf("   or when comparing floating-point values for equality.\n");
    
    // Security best practices
    printf("\n=== Security Best Practices ===\n");
    printf("1. Use fixed-width integer types when exact size is important\n");
    printf("2. Check for integer overflow/underflow in security-critical code\n");
    printf("3. Be careful with type conversions, especially signed/unsigned\n");
    printf("4. Use appropriate data types for the data being stored\n");
    printf("5. Validate input to ensure it fits within the expected range\n");
    
    return 0;
}

