/**
 * @file stack_buffer_overflow.cpp
 * @brief Demonstrates stack buffer overflow vulnerabilities and exploitation techniques
 * 
 * This file demonstrates how stack buffer overflows occur and how they can be
 * exploited. It includes examples of vulnerable code, exploitation techniques,
 * and mitigation strategies. Stack buffer overflows are a classic vulnerability
 * that occurs when data is written beyond the bounds of a buffer allocated on the stack.
 * 
 * WARNING: This code intentionally contains vulnerabilities for educational purposes.
 * Do not use these techniques on systems without proper authorization.
 * 
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 -fno-stack-protector -z execstack stack_buffer_overflow.cpp -o stack_buffer_overflow.exe
 * 
 * Red Team Applications:
 * - Exploiting vulnerable applications to gain code execution
 * - Bypassing non-ASLR enabled applications
 * - Understanding memory corruption vulnerabilities
 * - Developing custom exploits for penetration testing
 */

 #include <iostream>
 #include <cstring>
 #include <cstdlib>
 #include <iomanip>
 
 // Function prototypes
 void vulnerable_function(const char* input);
 void print_memory(const void* addr, size_t len);
 void demonstrate_stack_layout();
 void demonstrate_buffer_overflow();
 void demonstrate_mitigation();
 
 /**
  * @brief Main function that demonstrates different aspects of stack buffer overflows
  */
 int main(int argc, char* argv[]) {
     std::cout << "=== Stack Buffer Overflow Demonstration ===" << std::endl;
     std::cout << std::endl;
     
     // Demonstrate the stack layout
     std::cout << "1. Demonstrating Stack Layout:" << std::endl;
     demonstrate_stack_layout();
     std::cout << std::endl;
     
     // Demonstrate a buffer overflow
     std::cout << "2. Demonstrating Buffer Overflow:" << std::endl;
     demonstrate_buffer_overflow();
     std::cout << std::endl;
     
     // Demonstrate mitigation techniques
     std::cout << "3. Demonstrating Mitigation Techniques:" << std::endl;
     demonstrate_mitigation();
     
     return 0;
 }
 
 /**
  * @brief A vulnerable function that contains a stack buffer overflow vulnerability
  * 
  * This function allocates a fixed-size buffer on the stack and uses strcpy()
  * to copy the input string into the buffer without checking the length.
  * If the input string is longer than the buffer, a buffer overflow occurs.
  * 
  * @param input The input string to copy into the buffer
  */
 void vulnerable_function(const char* input) {
     char buffer[16]; // Small buffer on the stack
     
     // Vulnerable: No bounds checking
     strcpy(buffer, input);
     
     std::cout << "Buffer content: " << buffer << std::endl;
 }
 
 /**
  * @brief Prints a memory region as hexadecimal bytes and ASCII characters
  * 
  * @param addr Starting address of memory to print
  * @param len Number of bytes to print
  */
 void print_memory(const void* addr, size_t len) {
     const unsigned char* p = static_cast<const unsigned char*>(addr);
     
     for (size_t i = 0; i < len; i += 16) {
         // Print address
         std::cout << std::setw(8) << std::setfill('0') << std::hex << (uintptr_t)(p + i) << ": ";
         
         // Print hex bytes
         for (size_t j = 0; j < 16; j++) {
             if (i + j < len) {
                 std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(p[i + j]) << " ";
             } else {
                 std::cout << "   ";
             }
         }
         
         std::cout << " | ";
         
         // Print ASCII representation
         for (size_t j = 0; j < 16; j++) {
             if (i + j < len) {
                 unsigned char c = p[i + j];
                 if (c >= 32 && c <= 126) {
                     std::cout << c;
                 } else {
                     std::cout << ".";
                 }
             } else {
                 std::cout << " ";
             }
         }
         
         std::cout << std::endl;
     }
     
     std::cout << std::dec; // Reset to decimal
 }
 
 /**
  * @brief Demonstrates the layout of the stack
  * 
  * This function shows how local variables, function parameters, and the
  * return address are arranged on the stack.
  */
 void demonstrate_stack_layout() {
     // Allocate variables on the stack
     int a = 0x41414141;
     int b = 0x42424242;
     char buffer[16] = "BUFFER";
     int c = 0x43434343;
     
     // Print the addresses of the variables
     std::cout << "Address of a: " << &a << std::endl;
     std::cout << "Address of b: " << &b << std::endl;
     std::cout << "Address of buffer: " << static_cast<void*>(buffer) << std::endl;
     std::cout << "Address of c: " << &c << std::endl;
     
     // Print the stack memory
     std::cout << "Stack memory:" << std::endl;
     print_memory(&c - 8, 64); // Print a region of the stack
     
     std::cout << "Note how variables are arranged on the stack." << std::endl;
     std::cout << "In a typical x86 stack (growing downward):" << std::endl;
     std::cout << "- Higher addresses contain function parameters and return address" << std::endl;
     std::cout << "- Lower addresses contain local variables" << std::endl;
     std::cout << "- Buffer overflows can overwrite variables and the return address" << std::endl;
 }
 
 /**
  * @brief Demonstrates a buffer overflow vulnerability
  * 
  * This function shows how a buffer overflow can corrupt adjacent memory
  * and potentially lead to control flow hijacking.
  */
 void demonstrate_buffer_overflow() {
     // Safe input (fits in the buffer)
     std::cout << "Calling vulnerable_function with safe input:" << std::endl;
     vulnerable_function("Safe input");
     
     // Unsafe input (overflows the buffer)
     std::cout << "Calling vulnerable_function with unsafe input:" << std::endl;
     try {
         vulnerable_function("This is a very long input string that will overflow the buffer");
     } catch (...) {
         std::cout << "Exception caught! The program crashed due to buffer overflow." << std::endl;
     }
     
     std::cout << "In a real exploit scenario:" << std::endl;
     std::cout << "1. The overflow would overwrite the return address on the stack" << std::endl;
     std::cout << "2. When the function returns, execution would jump to the attacker-controlled address" << std::endl;
     std::cout << "3. This could lead to arbitrary code execution" << std::endl;
 }
 
 /**
  * @brief A safer version of the vulnerable function with bounds checking
  * 
  * @param input The input string to copy into the buffer
  */
 void safer_function(const char* input) {
     char buffer[16]; // Small buffer on the stack
     
     // Safe: Use strncpy with size limit and ensure null termination
     strncpy(buffer, input, sizeof(buffer) - 1);
     buffer[sizeof(buffer) - 1] = '\0';
     
     std::cout << "Buffer content: " << buffer << std::endl;
 }
 
 /**
  * @brief Demonstrates mitigation techniques for buffer overflows
  */
 void demonstrate_mitigation() {
     // Using safer functions
     std::cout << "Using safer functions with bounds checking:" << std::endl;
     safer_function("This is a very long input string that will be truncated");
     
     std::cout << std::endl;
     std::cout << "Other mitigation techniques include:" << std::endl;
     std::cout << "1. Stack canaries: Special values placed between buffers and control data" << std::endl;
     std::cout << "   - Compile with: -fstack-protector or -fstack-protector-all" << std::endl;
     std::cout << "2. Address Space Layout Randomization (ASLR)" << std::endl;
     std::cout << "   - Enabled by default on modern operating systems" << std::endl;
     std::cout << "   - Makes it harder to predict memory addresses" << std::endl;
     std::cout << "3. Data Execution Prevention (DEP) / Non-executable stack" << std::endl;
     std::cout << "   - Compile with: -z noexecstack" << std::endl;
     std::cout << "   - Prevents execution of code on the stack" << std::endl;
     std::cout << "4. Bounds checking at compile time or runtime" << std::endl;
     std::cout << "   - Use safer functions like strncpy, strncat, snprintf" << std::endl;
     std::cout << "   - Consider using std::string or other safer containers in C++" << std::endl;
 }
 
 