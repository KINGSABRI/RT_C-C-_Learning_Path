/**
 * @file format_string.cpp
 * @brief Demonstrates format string vulnerabilities and exploitation techniques
 *
 * This file demonstrates how format string vulnerabilities occur and how they
 * can be exploited. It includes examples of vulnerable code, exploitation techniques,
 * and mitigation strategies. Format string vulnerabilities occur when user-controlled
 * input is used directly as the format string in functions like printf.
 *
 * WARNING: This code intentionally contains vulnerabilities for educational purposes.
 * Do not use these techniques on systems without proper authorization.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 format_string.cpp -o format_string.exe
 *
 * Red Team Applications:
 * - Exploiting vulnerable applications to leak memory contents
 * - Overwriting memory to gain code execution
 * - Understanding memory corruption vulnerabilities
 * - Developing custom exploits for penetration testing
 */

#include <iostream>
#include <cstdio>
#include <cstring>
#include <iomanip>

// Function prototypes
void demonstrate_format_string_basics();
void demonstrate_format_string_leak();
void demonstrate_format_string_write();
void demonstrate_mitigation();
void print_memory(const void *addr, size_t len);

/**
 * @brief Main function that demonstrates different aspects of format string vulnerabilities
 */
int main()
{
    std::cout << "=== Format String Vulnerability Demonstration ===" << std::endl;
    std::cout << std::endl;

    // Demonstrate format string basics
    std::cout << "1. Format String Basics:" << std::endl;
    demonstrate_format_string_basics();
    std::cout << std::endl;

    // Demonstrate information leakage
    std::cout << "2. Information Leakage via Format Strings:" << std::endl;
    demonstrate_format_string_leak();
    std::cout << std::endl;

    // Demonstrate memory writes
    std::cout << "3. Memory Writes via Format Strings:" << std::endl;
    demonstrate_format_string_write();
    std::cout << std::endl;

    // Demonstrate mitigation techniques
    std::cout << "4. Mitigation Techniques:" << std::endl;
    demonstrate_mitigation();

    return 0;
}

/**
 * @brief A vulnerable function that contains a format string vulnerability
 *
 * @param format The format string, potentially controlled by the user
 */
void vulnerable_printf(const char *format)
{
    printf(format); // Vulnerable: user-controlled format string
}

/**
 * @brief A safer version of printf that uses a fixed format string
 *
 * @param str The string to print
 */
void safe_printf(const char *str)
{
    printf("%s", str); // Safe: fixed format string
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
 * @brief Demonstrates the basics of format string vulnerabilities
 */
void demonstrate_format_string_basics()
{
    std::cout << "Format strings control how printf and similar functions format output." << std::endl;
    std::cout << "Common format specifiers include:" << std::endl;
    std::cout << "- %s: String" << std::endl;
    std::cout << "- %d: Integer" << std::endl;
    std::cout << "- %x: Hexadecimal" << std::endl;
    std::cout << "- %p: Pointer" << std::endl;
    std::cout << "- %n: Write the number of bytes output so far to the specified variable" << std::endl;
    std::cout << std::endl;

    std::cout << "Normal usage (safe):" << std::endl;
    printf("String: %s, Number: %d, Hex: %x\n", "test", 42, 0xdeadbeef);

    std::cout << std::endl;
    std::cout << "Format string vulnerability occurs when user input is used as the format string:" << std::endl;

    // Safe usage
    const char *user_input = "Hello, world!";
    std::cout << "Safe: ";
    safe_printf(user_input);
    std::cout << std::endl;

    // Vulnerable usage
    std::cout << "Vulnerable: ";
    vulnerable_printf(user_input); // Safe in this case because the input doesn't contain format specifiers
    std::cout << std::endl;

    // Vulnerable usage with format specifiers
    const char *malicious_input = "Hello %x %x %x %x";
    std::cout << "Vulnerable with format specifiers: ";
    vulnerable_printf(malicious_input); // This will leak values from the stack
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << "When a format string vulnerability exists:" << std::endl;
    std::cout << "1. Format specifiers without corresponding arguments read from the stack" << std::endl;
    std::cout << "2. This can leak sensitive information from memory" << std::endl;
    std::cout << "3. The %n specifier can be used to write to memory" << std::endl;
}

/**
 * @brief Demonstrates information leakage via format string vulnerabilities
 */
void demonstrate_format_string_leak()
{
    // Create some data on the stack
    int secret_value = 0x12345678;
    char password[] = "s3cr3t_p4ssw0rd";

    std::cout << "Secret value: 0x" << std::hex << secret_value << std::dec << std::endl;
    std::cout << "Password: " << password << std::endl;

    std::cout << std::endl;
    std::cout << "Leaking stack values using format string vulnerability:" << std::endl;

    // Vulnerable printf with format specifiers to leak stack values
    std::cout << "Leak attempt: ";
    vulnerable_printf("Stack values: %x %x %x %x %x %x %x %x\n");

    std::cout << std::endl;
    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker would use %x or %p to leak values from the stack" << std::endl;
    std::cout << "2. By using multiple format specifiers, they can walk up the stack" << std::endl;
    std::cout << "3. This could reveal sensitive information like passwords, addresses, or canaries" << std::endl;
    std::cout << "4. Leaked addresses can be used to bypass ASLR" << std::endl;

    // Direct parameter access (more precise leaking)
    std::cout << std::endl;
    std::cout << "Direct parameter access (more precise leaking):" << std::endl;
    std::cout << "Leak attempt with direct access: ";
    vulnerable_printf("4th parameter: %4$x, 6th parameter: %6$x\n");
}

/**
 * @brief Demonstrates memory writes via format string vulnerabilities
 */
void demonstrate_format_string_write()
{
    // Target variable to be modified
    int target = 0;

    std::cout << "Target variable initial value: " << target << std::endl;

    // Create a format string that uses %n to write to the target variable
    // Note: This is simplified and might not work as shown due to compiler optimizations
    // and stack layout. In a real exploit, more complex techniques would be used.

    std::cout << "Attempting to modify target variable using %n..." << std::endl;
    printf("Before %n\n", &target);

    std::cout << "Target variable after %n: " << target << std::endl;
    std::cout << "The value written is the number of characters output before the %n" << std::endl;

    std::cout << std::endl;
    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker would use %n to write to a specific memory address" << std::endl;
    std::cout << "2. The value written would be the number of characters output so far" << std::endl;
    std::cout << "3. By controlling the output length, they can write arbitrary values" << std::endl;
    std::cout << "4. This could be used to overwrite function pointers, return addresses, or other critical data" << std::endl;
    std::cout << "5. Partial writes (%hn, %hhn) can be used to write specific bytes" << std::endl;

    std::cout << std::endl;
    std::cout << "Advanced techniques:" << std::endl;
    std::cout << "- Write arbitrary values by controlling the output length" << std::endl;
    std::cout << "- Use multiple %n to write to different addresses" << std::endl;
    std::cout << "- Use direct parameter access to control which arguments are used" << std::endl;
}

/**
 * @brief Demonstrates mitigation techniques for format string vulnerabilities
 */
void demonstrate_mitigation()
{
    const char *user_input = "Potentially malicious input with %x %x %x";

    std::cout << "1. Always use a fixed format string:" << std::endl;
    std::cout << "   Vulnerable: printf(user_input);" << std::endl;
    std::cout << "   Safe: printf(\"%s\", user_input);" << std::endl;

    // Demonstrate the safe approach
    std::cout << "   Result of safe approach: ";
    safe_printf(user_input);
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << "2. Use C++ stream objects which are not vulnerable to format string issues:" << std::endl;
    std::cout << "   std::cout << user_input;" << std::endl;

    // Demonstrate C++ streams
    std::cout << "   Result of C++ streams: " << user_input << std::endl;

    std::cout << std::endl;
    std::cout << "3. Use safer C functions:" << std::endl;
    std::cout << "   - puts() instead of printf() for simple string output" << std::endl;
    std::cout << "   - snprintf() with size limits for formatted output" << std::endl;

    std::cout << std::endl;
    std::cout << "4. Compiler protections:" << std::endl;
    std::cout << "   - Some compilers warn about format string vulnerabilities" << std::endl;
    std::cout << "   - Use -Wformat -Wformat-security flags with GCC/Clang" << std::endl;
    std::cout << "   - Use /GS flag with MSVC" << std::endl;

    std::cout << std::endl;
    std::cout << "5. Runtime protections:" << std::endl;
    std::cout << "   - FormatGuard: Detects format string attacks at runtime" << std::endl;
    std::cout << "   - libsafe: Provides safer versions of vulnerable functions" << std::endl;

    std::cout << std::endl;
    std::cout << "6. Code review and static analysis:" << std::endl;
    std::cout << "   - Regularly review code for format string vulnerabilities" << std::endl;
    std::cout << "   - Use static analysis tools to detect potential issues" << std::endl;
    std::cout << "   - Follow secure coding guidelines" << std::endl;
}
