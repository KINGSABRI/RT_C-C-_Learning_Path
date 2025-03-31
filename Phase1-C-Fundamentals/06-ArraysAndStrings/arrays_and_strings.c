/**
 * Arrays and Strings in C - Cybersecurity Perspective
 * 
 * This program demonstrates arrays and strings in C with a focus on
 * security implications and best practices.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Function to demonstrate basic array operations
void demonstrate_arrays() {
    printf("\n=== Basic Array Operations ===\n");
    
    // Declare and initialize an array
    int scores[5] = {85, 92, 78, 90, 88};
    
    // Access and print array elements
    printf("Security audit scores:\n");
    for (int i = 0; i < 5; i++) {
        printf("System %d: %d/100\n", i + 1, scores[i]);
    }
    
    // Calculate average score
    int sum = 0;
    for (int i = 0; i < 5; i++) {
        sum += scores[i];
    }
    float average = (float)sum / 5;
    printf("Average security score: %.2f\n", average);
    
    // Find the system with the lowest security score
    int min_score = scores[0];
    int min_index = 0;
    
    for (int i = 1; i < 5; i++) {
        if (scores[i] < min_score) {
            min_score = scores[i];
            min_index = i;
        }
    }
    
    printf("System %d has the lowest security score: %d/100\n", min_index + 1, min_score);
    
    // Demonstrate array bounds
    printf("\nArray bounds demonstration:\n");
    printf("Array size: 5 elements\n");
    printf("Valid indices: 0-4\n");
    
    // Accessing within bounds
    printf("scores[4] = %d (valid access)\n", scores[4]);
    
    // WARNING: The following line demonstrates a security vulnerability
    // Accessing out of bounds - this can lead to undefined behavior
    // Commented out to prevent actual issues
    // printf("scores[10] = %d (invalid access - undefined behavior)\n", scores[10]);
    
    printf("Accessing array elements outside the valid range can lead to:\n");
    printf("1. Reading unintended memory (information disclosure)\n");
    printf("2. Overwriting unintended memory (buffer overflow)\n");
    printf("3. Program crashes or unpredictable behavior\n");
}

// Function to demonstrate multi-dimensional arrays
void demonstrate_multi_arrays() {
    printf("\n=== Multi-dimensional Arrays ===\n");
    
    // 2D array representing a network access control matrix
    // Rows represent users, columns represent resources
    // 0 = no access, 1 = read access, 2 = write access, 3 = full access
    int access_matrix[4][5] = {
        {3, 3, 3, 3, 3},  // Admin (user 0) has full access to all resources
        {1, 1, 0, 0, 0},  // Guest (user 1) has limited read access
        {2, 2, 1, 0, 0},  // Developer (user 2) has mixed access
        {3, 0, 0, 0, 0}   // Manager (user 3) has access to resource 0 only
    };
    
    // User names and resource names for better readability
    char* users[] = {"Admin", "Guest", "Developer", "Manager"};
    char* resources[] = {"Public Web", "Internal Wiki", "Code Repo", "Customer DB", "Admin Panel"};
    
    // Print the access matrix
    printf("Network Access Control Matrix:\n\n");
    
    // Print header row with resource names
    printf("%-10s", "User\\Res");
    for (int j = 0; j < 5; j++) {
        printf("%-15s", resources[j]);
    }
    printf("\n");
    
    // Print separator line
    for (int j = 0; j < 85; j++) {
        printf("-");
    }
    printf("\n");
    
    // Print access matrix with user names
    for (int i = 0; i < 4; i++) {
        printf("%-10s", users[i]);
        
        for (int j = 0; j < 5; j++) {
            char* access_type;
            switch (access_matrix[i][j]) {
                case 0: access_type = "None"; break;
                case 1: access_type = "Read"; break;
                case 2: access_type = "Write"; break;
                case 3: access_type = "Full"; break;
                default: access_type = "Unknown";
            }
            printf("%-15s", access_type);
        }
        printf("\n");
    }
    
    // Demonstrate access check
    int user = 2;  // Developer
    int resource = 3;  // Customer DB
    
    printf("\nAccess check: Does %s have access to %s?\n", users[user], resources[resource]);
    
    if (access_matrix[user][resource] > 0) {
        printf("Access granted (level %d)\n", access_matrix[user][resource]);
    } else {
        printf("Access denied\n");
    }
}

// Function to demonstrate basic string operations
void demonstrate_strings() {
    printf("\n=== Basic String Operations ===\n");
    
    // String declaration and initialization
    char greeting[] = "Hello, Security Student!";
    
    // Print the string
    printf("Greeting: %s\n", greeting);
    
    // String length
    printf("Length: %zu characters\n", strlen(greeting));
    
    // String copy (safe version)
    char greeting_copy[50];
    strncpy(greeting_copy, greeting, sizeof(greeting_copy) - 1);
    greeting_copy[sizeof(greeting_copy) - 1] = '\0';  // Ensure null termination
    printf("Copy: %s\n", greeting_copy);
    
    // String comparison
    if (strcmp(greeting, greeting_copy) == 0) {
        printf("Strings are identical\n");
    } else {
        printf("Strings are different\n");
    }
    
    // String concatenation (safe version)
    char message[100] = "Welcome to ";
    strncat(message, "Cybersecurity Programming", sizeof(message) - strlen(message) - 1);
    printf("Concatenated: %s\n", message);
    
    // String searching
    char* found = strstr(greeting, "Security");
    if (found != NULL) {
        printf("Found 'Security' at position: %ld\n", found - greeting);
    } else {
        printf("'Security' not found in the string\n");
    }
}

// Function to demonstrate string vulnerabilities and safe alternatives
void demonstrate_string_security() {
    printf("\n=== String Security ===\n");
    
    // Vulnerable string functions vs. safe alternatives
    printf("Vulnerable vs. Safe String Functions:\n");
    
    char src[50] = "Sensitive data that should be handled securely";
    char dest1[20];  // Intentionally too small
    char dest2[20];  // Intentionally too small
    
    printf("Source string: \"%s\" (length: %zu)\n", src, strlen(src));
    printf("Destination buffer size: 20 bytes\n\n");
    
    // Vulnerable function (strcpy)
    printf("1. Vulnerable function: strcpy()\n");
    printf("   - No bounds checking\n");
    printf("   - Can cause buffer overflow\n");
    printf("   - Example: strcpy(dest1, src); // DANGEROUS!\n");
    // strcpy(dest1, src);  // Commented out to prevent actual buffer overflow
    
    // Safe alternative (strncpy)
    printf("\n2. Safe alternative: strncpy()\n");
    printf("   - Performs bounds checking\n");
    printf("   - Prevents buffer overflow\n");
    strncpy(dest2, src, sizeof(dest2) - 1);
    dest2[sizeof(dest2) - 1] = '\0';  // Ensure null termination
    printf("   - Result: \"%s\" (truncated safely)\n", dest2);
    
    // Other vulnerable functions and their safe alternatives
    printf("\nOther vulnerable functions and their safe alternatives:\n");
    printf("- gets() -> fgets()\n");
    printf("- sprintf() -> snprintf()\n");
    printf("- strcat() -> strncat()\n");
    
    // Demonstrate format string vulnerability
    printf("\nFormat String Vulnerability:\n");
    char user_input[] = "Hello %x %x %x";  // Simulated malicious input
    
    printf("Malicious input: \"%s\"\n", user_input);
    
    printf("Vulnerable code: printf(user_input); // DANGEROUS!\n");
    printf("Safe code: printf(\"%%s\", user_input);\n");
    
    // Demonstrate the safe way
    printf("Safe output: %s\n", user_input);
}

// Function to sanitize user input
void sanitize_input(char* input) {
    // Remove any non-alphanumeric characters except spaces
    int i, j = 0;
    for (i = 0; input[i] != '\0'; i++) {
        if (isalnum(input[i]) || input[i] == ' ') {
            input[j++] = input[i];
        }
    }
    input[j] = '\0';
}

// Function to demonstrate input validation
void demonstrate_input_validation() {
    printf("\n=== Input Validation ===\n");
    
    // Simulated user inputs
    char username1[] = "admin";
    char username2[] = "admin; DROP TABLE users;";  // SQL injection attempt
    char username3[] = "<script>alert('XSS')</script>";  // XSS attempt
    
    printf("Original inputs:\n");
    printf("1. \"%s\"\n", username1);
    printf("2. \"%s\"\n", username2);
    printf("3. \"%s\"\n", username3);
    
    // Sanitize inputs
    sanitize_input(username1);
    sanitize_input(username2);
    sanitize_input(username3);
    
    printf("\nAfter sanitization:\n");
    printf("1. \"%s\"\n", username1);
    printf("2. \"%s\"\n", username2);
    printf("3. \"%s\"\n", username3);
    
    printf("\nInput validation is crucial for preventing:\n");
    printf("1. SQL Injection\n");
    printf("2. Cross-Site Scripting (XSS)\n");
    printf("3. Command Injection\n");
    printf("4. Buffer Overflows\n");
}

// Function to demonstrate a simple encryption/decryption
void demonstrate_encryption() {
    printf("\n=== Simple String Encryption/Decryption ===\n");
    
    // Original message
    char message[] = "Confidential: Security breach in progress";
    printf("Original message: \"%s\"\n", message);
    
    // Encryption key (simple XOR key)
    unsigned char key = 0x5A;
    
    // Encrypt the message
    printf("Encrypting...\n");
    for (int i = 0; message[i] != '\0'; i++) {
        message[i] = message[i] ^ key;
    }
    
    printf("Encrypted message (hex): ");
    for (int i = 0; message[i] != '\0'; i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n");
    
    // Decrypt the message
    printf("Decrypting...\n");
    for (int i = 0; message[i] != '\0'; i++) {
        message[i] = message[i] ^ key;
    }
    
    printf("Decrypted message: \"%s\"\n", message);
    
    printf("\nNote: This is a very simple XOR cipher for demonstration only.\n");
    printf("Real-world applications should use established cryptographic libraries.\n");
}

int main() {
    printf("=== Arrays and Strings in C: Cybersecurity Perspective ===\n");
    
    // Demonstrate arrays
    demonstrate_arrays();
    
    // Demonstrate multi-dimensional arrays
    demonstrate_multi_arrays();
    
    // Demonstrate strings
    demonstrate_strings();
    
    // Demonstrate string security
    demonstrate_string_security();
    
    // Demonstrate input validation
    demonstrate_input_validation();
    
    // Demonstrate simple encryption
    demonstrate_encryption();
    
    printf("\n=== Security Best Practices for Arrays and Strings ===\n");
    printf("1. Always check array bounds before accessing elements\n");
    printf("2. Use safe string functions with bounds checking\n");
    printf("3. Always ensure strings are null-terminated\n");
    printf("4. Validate and sanitize all user input\n");
    printf("5. Be cautious with format strings\n");
    printf("6. Use established cryptographic libraries for encryption\n");
    
    return 0;
}

