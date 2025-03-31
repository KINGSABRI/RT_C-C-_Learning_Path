/**
 * Buffer Overflow Demonstration
 * 
 * This program demonstrates buffer overflow vulnerabilities and how to prevent them.
 * WARNING: For educational purposes only!
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// This function is vulnerable to buffer overflow
void vulnerable_function(char *input) {
    char buffer[16]; // Small buffer

    // Unsafe! No bounds checking
    strcpy(buffer, input);

    printf("Buffer content: %s\n", buffer);
    printf("Buffer size: 16 bytes\n");
    printf("Input length: %zu bytes\n", strlen(input) + 1); // +1 for null terminator
}

// This function is protected against buffer overflow
void secure_function(char *input) {
    char buffer[16];

    // Safe: uses bounded copy
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination

    printf("Buffer content (secure): %s\n", buffer);
    printf("Buffer size: 16 bytes\n");
    printf("Input length: %zu bytes\n", strlen(input) + 1);
}

// Function to demonstrate stack variables
void demonstrate_stack_variables() {
    int a = 1;
    int b = 2;
    int c = 3;

    char buffer[16];

    printf("\nStack variable addresses:\n");
    printf("Address of a: %p\n", (void*)&a);
    printf("Address of b: %p\n", (void*)&b);
    printf("Address of c: %p\n", (void*)&c);
    printf("Address of buffer: %p\n", (void*)buffer);

    printf("\nInitial values:\n");
    printf("a = %d, b = %d, c = %d\n", a, b, c);

    // Simulate buffer overflow by writing beyond buffer's bounds
    printf("\nSimulating controlled buffer overflow...\n");

    // This is for demonstration only - NEVER do this in real code!
    // We're showing how buffer overflow can corrupt adjacent variables
    for (int i = 0; i < 30; i++) {
        buffer[i] = 'A';
    }

    printf("After overflow:\n");
    printf("a = %d, b = %d, c = %d\n", a, b, c);
    printf("Buffer content: %.16s...\n", buffer);

    printf("\nThis demonstrates how buffer overflow can corrupt adjacent memory!\n");
}

int main(int argc, char *argv[]) {
    printf("=== Buffer Overflow Demonstration ===\n");
    printf("This program demonstrates buffer overflow vulnerabilities.\n");
    printf("WARNING: For educational purposes only!\n\n");

    // Demonstrate stack variables and overflow
    demonstrate_stack_variables();

    // Test with a short input (safe)
    char *short_input = "Short";
    printf("\n=== Testing with short input ===\n");
    printf("Input: %s\n", short_input);

    printf("\nVulnerable function:\n");
    vulnerable_function(short_input);

    printf("\nSecure function:\n");
    secure_function(short_input);

    // Test with a long input (causes overflow in vulnerable function)
    char *long_input = "This is a very long input string that will definitely overflow the buffer";
    printf("\n=== Testing with long input ===\n");
    printf("Input: %s\n", long_input);

    printf("\nVulnerable function:\n");
    vulnerable_function(long_input);

    printf("\nSecure function:\n");
    secure_function(long_input);

    printf("\n=== Security Lessons ===\n");
    printf("1. Always check buffer sizes before copying data\n");
    printf("2. Use bounded string functions like strncpy(), strncat()\n");
    printf("3. Ensure strings are null-terminated after bounded operations\n");
    printf("4. Consider using safer alternatives like snprintf()\n");
    printf("5. In security-critical code, validate all input\n");

    return 0;
}

