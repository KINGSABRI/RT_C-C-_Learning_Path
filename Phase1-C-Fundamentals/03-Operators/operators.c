/**
 * Operators in C - Cybersecurity Perspective
 * 
 * This program demonstrates various operators in C and their
 * security implications.
 */

#include <stdio.h>
#include <stdbool.h>  // For bool type

int main() {
    printf("=== Operators in C: Cybersecurity Perspective ===\n\n");
    
    // Arithmetic operators
    printf("=== Arithmetic Operators ===\n");
    int a = 10, b = 3;
    printf("a = %d, b = %d\n", a, b);
    printf("a + b = %d\n", a + b);  // Addition
    printf("a - b = %d\n", a - b);  // Subtraction
    printf("a * b = %d\n", a * b);  // Multiplication
    printf("a / b = %d\n", a / b);  // Division (integer division)
    printf("a %% b = %d\n", a % b); // Modulus (remainder)
    
    // Increment and decrement
    int c = 5;
    printf("\nIncrement and Decrement:\n");
    printf("c = %d\n", c);
    printf("++c = %d\n", ++c);  // Pre-increment
    printf("c++ = %d\n", c++);  // Post-increment
    printf("After c++, c = %d\n", c);
    printf("--c = %d\n", --c);  // Pre-decrement
    printf("c-- = %d\n", c--);  // Post-decrement
    printf("After c--, c = %d\n", c);
    
    // Assignment operators
    printf("\n=== Assignment Operators ===\n");
    int d = 10;
    printf("d = %d\n", d);
    
    d += 5;  // d = d + 5
    printf("d += 5: %d\n", d);
    
    d -= 3;  // d = d - 3
    printf("d -= 3: %d\n", d);
    
    d *= 2;  // d = d * 2
    printf("d *= 2: %d\n", d);
    
    d /= 4;  // d = d / 4
    printf("d /= 4: %d\n", d);
    
    d %= 2;  // d = d % 2
    printf("d %%= 2: %d\n", d);
    
    // Comparison operators
    printf("\n=== Comparison Operators ===\n");
    int x = 10, y = 20;
    printf("x = %d, y = %d\n", x, y);
    printf("x == y: %d\n", x == y);  // Equal to
    printf("x != y: %d\n", x != y);  // Not equal to
    printf("x > y: %d\n", x > y);    // Greater than
    printf("x < y: %d\n", x < y);    // Less than
    printf("x >= y: %d\n", x >= y);  // Greater than or equal to
    printf("x <= y: %d\n", x <= y);  // Less than or equal to
    
    // Logical operators
    printf("\n=== Logical Operators ===\n");
    bool p = true, q = false;
    printf("p = %d, q = %d\n", p, q);
    printf("p && q: %d\n", p && q);  // Logical AND
    printf("p || q: %d\n", p || q);  // Logical OR
    printf("!p: %d\n", !p);          // Logical NOT
    
    // Bitwise operators
    printf("\n=== Bitwise Operators ===\n");
    unsigned int m = 0x0F, n = 0xA5;
    printf("m = 0x%X, n = 0x%X\n", m, n);
    printf("m & n = 0x%X\n", m & n);    // Bitwise AND
    printf("m | n = 0x%X\n", m | n);    // Bitwise OR
    printf("m ^ n = 0x%X\n", m ^ n);    // Bitwise XOR
    printf("~m = 0x%X\n", ~m);          // Bitwise NOT
    printf("m << 2 = 0x%X\n", m << 2);  // Left shift
    printf("n >> 2 = 0x%X\n", n >> 2);  // Right shift
    
    // Other operators
    printf("\n=== Other Operators ===\n");
    int arr[5] = {10, 20, 30, 40, 50};
    printf("arr[2] = %d\n", arr[2]);  // Array subscript
    
    int *ptr = &a;
    printf("a = %d, &a = %p, ptr = %p, *ptr = %d\n", a, &a, ptr, *ptr);  // Pointer operations
    
    int size = sizeof(a);
    printf("sizeof(a) = %d bytes\n", size);  // Size of variable
    
    // Conditional (ternary) operator
    printf("\n=== Conditional Operator ===\n");
    int max = (a > b) ? a : b;
    printf("max of %d and %d is %d\n", a, b, max);
    
    // Security implications
    printf("\n=== Security Implications ===\n");
    
    // 1. Integer overflow/underflow
    printf("\n1. Integer Overflow/Underflow:\n");
    int max_val = __INT_MAX__;
    printf("   INT_MAX = %d\n", max_val);
    printf("   INT_MAX + 1 = %d (overflow!)\n", max_val + 1);
    
    int min_val = -__INT_MAX__ - 1;
    printf("   INT_MIN = %d\n", min_val);
    printf("   INT_MIN - 1 = %d (underflow!)\n", min_val - 1);
    
    // 2. Signed vs unsigned comparison
    printf("\n2. Signed vs Unsigned Comparison:\n");
    unsigned int u = 10;
    int s = -5;
    printf("   unsigned u = %u, signed s = %d\n", u, s);
    printf("   u > s? %s\n", (u > s) ? "true" : "false");
    printf("   This is counterintuitive because -5 gets converted to a very large unsigned value!\n");
    
    // 3. Bitwise operations for access control
    printf("\n3. Bitwise Operations for Access Control:\n");
    unsigned char permissions = 0x00;  // No permissions initially
    
    // Define permission bits
    const unsigned char READ = 0x04;   // 00000100
    const unsigned char WRITE = 0x02;  // 00000010
    const unsigned char EXEC = 0x01;   // 00000001
    
    // Grant read and write permissions
    permissions |= (READ | WRITE);
    printf("   Permissions after granting READ and WRITE: 0x%02X\n", permissions);
    
    // Check if has read permission
    printf("   Has READ permission? %s\n", (permissions & READ) ? "Yes" : "No");
    
    // Revoke write permission
    permissions &= ~WRITE;
    printf("   Permissions after revoking WRITE: 0x%02X\n", permissions);
    
    printf("   Has WRITE permission? %s\n", (permissions & WRITE) ? "Yes" : "No");
    
    // 4. Short-circuit evaluation for safe pointer operations
    printf("\n4. Short-circuit Evaluation for Safe Pointer Operations:\n");
    int *safe_ptr = NULL;
    
    // This is safe because the first condition is false, so the second is not evaluated
    if (safe_ptr != NULL && *safe_ptr == 10) {
        printf("   Pointer value is 10\n");
    } else {
        printf("   Safe: Avoided dereferencing NULL pointer using short-circuit evaluation\n");
    }
    
    // 5. Operator precedence issues
    printf("\n5. Operator Precedence Issues:\n");
    int val = 5;
    int result1 = val + 3 * 2;
    int result2 = (val + 3) * 2;
    printf("   val + 3 * 2 = %d (multiplication has higher precedence)\n", result1);
    printf("   (val + 3) * 2 = %d (parentheses change precedence)\n", result2);
    
    // Security best practices
    printf("\n=== Security Best Practices ===\n");
    printf("1. Be aware of integer overflow/underflow in security-critical code\n");
    printf("2. Use parentheses to clarify operator precedence\n");
    printf("3. Be cautious with signed vs unsigned comparisons\n");
    printf("4. Use short-circuit evaluation for null pointer safety\n");
    printf("5. Consider bounds checking before array access\n");
    printf("6. Use bitwise operations for flags and permissions\n");
    
    return 0;
}

