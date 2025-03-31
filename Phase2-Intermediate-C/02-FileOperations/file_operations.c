/**
 * File Operations in C - Cybersecurity Perspective
 * 
 * This program demonstrates file operations in C with a focus on
 * security implications and best practices.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define MAX_LINE_LENGTH 1024
#define MAX_FILENAME_LENGTH 256
#define LOG_BUFFER_SIZE 2048

// Function to demonstrate basic file operations
void demonstrate_basic_file_operations() {
    printf("\n=== Basic File Operations ===\n");
    
    // Create a file for writing
    FILE *file = fopen("test_file.txt", "w");
    
    // Check if file was opened successfully
    if (file == NULL) {
        printf("Error opening file for writing: %s\n", strerror(errno));
        return;
    }
    
    // Write to the file
    fprintf(file, "This is a test file.\n");
    fprintf(file, "It contains some sensitive information:\n");
    fprintf(file, "Username: admin\n");
    fprintf(file, "Password: secure_password123\n");
    
    // Close the file
    fclose(file);
    printf("File 'test_file.txt' created and written successfully.\n");
    
    // Open the file for reading
    file = fopen("test_file.txt", "r");
    
    // Check if file was opened successfully
    if (file == NULL) {
        printf("Error opening file for reading: %s\n", strerror(errno));
        return;
    }
    
    // Read from the file
    char line[MAX_LINE_LENGTH];
    printf("\nFile contents:\n");
    printf("-------------\n");
    
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }
    printf("-------------\n");
    
    // Close the file
    fclose(file);
    
    // Append to the file
    file = fopen("test_file.txt", "a");
    
    // Check if file was opened successfully
    if (file == NULL) {
        printf("Error opening file for appending: %s\n", strerror(errno));
        return;
    }
    
    // Append to the file
    fprintf(file, "\nThis line was appended.\n");
    fprintf(file, "Timestamp: %ld\n", (long)time(NULL));
    
    // Close the file
    fclose(file);
    printf("\nFile appended successfully.\n");
    
    // Read the file again to show the appended content
    file = fopen("test_file.txt", "r");
    
    // Check if file was opened successfully
    if (file == NULL) {
        printf("Error opening file for reading: %s\n", strerror(errno));
        return;
    }
    
    // Read from the file
    printf("\nUpdated file contents:\n");
    printf("-------------\n");
    
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }
    printf("-------------\n");
    
    // Close the file
    fclose(file);
}

// Function to demonstrate secure file operations
void demonstrate_secure_file_operations() {
    printf("\n=== Secure File Operations ===\n");
    
    // 1. Path traversal prevention
    printf("1. Path Traversal Prevention:\n");
    
    // Simulated user input (potentially malicious)
    const char *user_input = "../../../etc/passwd";
    
    printf("   User requested file: %s\n", user_input);
    
    // Check for path traversal attempts
    if (strstr(user_input, "..") != NULL || user_input[0] == '/') {
        printf("   SECURITY ALERT: Path traversal attempt detected!\n");
        printf("   Access denied.\n");
    } else {
        printf("   File access would be allowed (safe path).\n");
    }
    
    // 2. Proper error handling
    printf("\n2. Proper Error Handling:\n");
    
    FILE *file = fopen("nonexistent_file.txt", "r");
    
    if (file == NULL) {
        printf("   Error opening file: %s (errno: %d)\n", strerror(errno), errno);
        
        // Different handling based on error type
        switch (errno) {
            case ENOENT:
                printf("   File does not exist.\n");
                break;
            case EACCES:
                printf("   Permission denied.\n");
                break;
            default:
                printf("   Unknown error occurred.\n");
        }
    } else {
        // This won't execute since the file doesn't exist
        fclose(file);
    }
    
    // 3. Secure temporary files
    printf("\n3. Secure Temporary Files:\n");
    
    // Create a temporary file
    char temp_filename[MAX_FILENAME_LENGTH];
    
    // Generate a unique temporary filename
    snprintf(temp_filename, sizeof(temp_filename), "temp_%ld_%d.txt", 
             (long)time(NULL), rand() % 10000);
    
    printf("   Creating temporary file: %s\n", temp_filename);
    
    FILE *temp_file = fopen(temp_filename, "w");
    
    if (temp_file == NULL) {
        printf("   Error creating temporary file: %s\n", strerror(errno));
    } else {
        // Write some data to the temporary file
        fprintf(temp_file, "This is sensitive temporary data.\n");
        
        // Close the file
        fclose(temp_file);
        
        printf("   Temporary file created successfully.\n");
        
        // Process the temporary file...
        printf("   Processing temporary file...\n");
        
        // Delete the temporary file when done
        if (remove(temp_filename) == 0) {
            printf("   Temporary file deleted successfully.\n");
        } else {
            printf("   Error deleting temporary file: %s\n", strerror(errno));
        }
    }
    
    // 4. File permissions (note: this is platform-specific)
    printf("\n4. File Permissions:\n");
    printf("   On Unix-like systems, you should set appropriate file permissions:\n");
    printf("   - Sensitive files: 0600 (user read/write only)\n");
    printf("   - Configuration files: 0644 (user read/write, others read-only)\n");
    printf("   - Executable files: 0755 (user read/write/execute, others read/execute)\n");
    
    // Example of how to check file permissions (Unix-specific)
    #ifdef __unix__
    printf("\n   Checking permissions of 'test_file.txt':\n");
    system("ls -l test_file.txt");
    #endif
}

// Function to demonstrate binary file operations
void demonstrate_binary_file_operations() {
    printf("\n=== Binary File Operations ===\n");
    
    // Structure to store in binary file
    typedef struct {
        int id;
        char username[32];
        char email[64];
        time_t created_at;
    } User;
    
    // Create some user records
    User users[3] = {
        {1, "admin", "admin@example.com", time(NULL)},
        {2, "user1", "user1@example.com", time(NULL)},
        {3, "user2", "user2@example.com", time(NULL)}
    };
    
    // Write to binary file
    FILE *file = fopen("users.bin", "wb");
    
    if (file == NULL) {
        printf("Error opening binary file for writing: %s\n", strerror(errno));
        return;
    }
    
    // Write the number of users
    int num_users = 3;
    fwrite(&num_users, sizeof(int), 1, file);
    
    // Write the user records
    fwrite(users, sizeof(User), num_users, file);
    
    // Close the file
    fclose(file);
    printf("Binary file 'users.bin' created with %d user records.\n", num_users);
    
    // Read from binary file
    file = fopen("users.bin", "rb");
    
    if (file == NULL) {
        printf("Error opening binary file for reading: %s\n", strerror(errno));
        return;
    }
    
    // Read the number of users
    int read_num_users;
    fread(&read_num_users, sizeof(int), 1, file);
    
    // Allocate memory for user records
    User *read_users = (User*)malloc(read_num_users * sizeof(User));
    
    if (read_users == NULL) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return;
    }
    
    // Read the user records
    fread(read_users, sizeof(User), read_num_users, file);
    
    // Close the file
    fclose(file);
    
    // Display the read records
    printf("\nRead %d user records from binary file:\n", read_num_users);
    
    for (int i = 0; i < read_num_users; i++) {
        char time_str[30];
        struct tm *timeinfo = localtime(&read_users[i].created_at);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        printf("User #%d:\n", read_users[i].id);
        printf("  Username: %s\n", read_users[i].username);
        printf("  Email: %s\n", read_users[i].email);
        printf("  Created: %s\n", time_str);
        printf("\n");
    }
    
    // Free allocated memory
    free(read_users);
    
    // Security implications
    printf("Security implications of binary files:\n");
    printf("1. Binary files can contain sensitive data that's not immediately visible\n");
    printf("2. They can be harder to inspect for malicious content\n");
    printf("3. Ensure proper validation when reading binary data\n");
    printf("4. Be cautious with structure padding and alignment\n");
}

// Function to implement a simple secure logging system
void demonstrate_secure_logging() {
    printf("\n=== Secure Logging System ===\n");
    
    // Log levels
    typedef enum {
        LOG_DEBUG,
        LOG_INFO,
        LOG_WARNING,
        LOG_ERROR,
        LOG_CRITICAL
    } LogLevel;
    
    // Function to get log level name
    const char* get_log_level_name(LogLevel level) {
        switch (level) {
            case LOG_DEBUG: return "DEBUG";
            case LOG_INFO: return "INFO";
            case LOG_WARNING: return "WARNING";
            case LOG_ERROR: return "ERROR";
            case LOG_CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }
    
    // Function to write a log entry
    void write_log(LogLevel level, const char *message) {
        // Open log file in append mode
        FILE *log_file = fopen("security.log", "a");
        
        if (log_file == NULL) {
            printf("Error opening log file: %s\n", strerror(errno));
            return;
        }
        
        // Get current time
        time_t now = time(NULL);
        struct tm *timeinfo = localtime(&now);
        char time_str[30];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        // Format log message
        char log_buffer[LOG_BUFFER_SIZE];
        snprintf(log_buffer, sizeof(log_buffer), "[%s] [%s] %s\n", 
                 time_str, get_log_level_name(level), message);
        
        // Write to log file
        fputs(log_buffer, log_file);
        
        // Close log file
        fclose(log_file);
        
        // Also print to console for demonstration
        printf("%s", log_buffer);
    }
    
    // Demonstrate logging
    printf("Writing log entries to 'security.log':\n");
    
    write_log(LOG_INFO, "System startup");
    write_log(LOG_DEBUG, "Configuration loaded from config.ini");
    write_log(LOG_INFO, "User 'admin' logged in from 192.168.1.100");
    write_log(LOG_WARNING, "Failed login attempt for user 'root' from 10.0.0.5");
    write_log(LOG_ERROR, "Database connection failed: Connection timeout");
    write_log(LOG_CRITICAL, "Possible intrusion detected: Multiple failed login attempts from 10.0.0.5");
    
    printf("\nLog file created successfully.\n");
    
    // Security considerations for logging
    printf("\nSecurity considerations for logging:\n");
    printf("1. Ensure logs don't contain sensitive information (passwords, tokens, etc.)\n");
    printf("2. Protect log files with appropriate permissions\n");
    printf("3. Implement log rotation to prevent disk space exhaustion\n");
    printf("4. Consider using a centralized logging system\n");
    printf("5. Ensure logs are tamper-evident (e.g., using digital signatures)\n");
}

// Function to demonstrate configuration file parsing
void demonstrate_config_parsing() {
    printf("\n=== Configuration File Parsing ===\n");
    
    // Create a sample configuration file
    FILE *config_file = fopen("config.ini", "w");
    
    if (config_file == NULL) {
        printf("Error creating configuration file: %s\n", strerror(errno));
        return;
    }
    
    // Write sample configuration
    fprintf(config_file, "# Security Configuration\n");
    fprintf(config_file, "\n");
    fprintf(config_file, "[General]\n");
    fprintf(config_file, "debug_mode = false\n");
    fprintf(config_file, "log_level = INFO\n");
    fprintf(config_file, "\n");
    fprintf(config_file, "[Network]\n");
    fprintf(config_file, "port = 8080\n");
    fprintf(config_file, "max_connections = 100\n");
    fprintf(config_file, "timeout = 30\n");
    fprintf(config_file, "\n");
    fprintf(config_file, "[Security]\n");
    fprintf(config_file, "enable_firewall = true\n");
    fprintf(config_file, "max_login_attempts = 3\n");
    fprintf(config_file, "password_min_length = 12\n");
    fprintf(config_file, "allowed_ips = 192.168.1.0/24,10.0.0.1\n");
    
    // Close the file
    fclose(config_file);
    printf("Sample configuration file 'config.ini' created.\n");
    
    // Simple configuration parser
    printf("\nParsing configuration file:\n");
    
    config_file = fopen("config.ini", "r");
    
    if (config_file == NULL) {
        printf("Error opening configuration file: %s\n", strerror(errno));
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    char current_section[64] = "";
    
    while (fgets(line, sizeof(line), config_file) != NULL) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        // Check for section header
        if (line[0] == '[' && line[len - 2] == ']') {
            strncpy(current_section, line + 1, len - 3);
            current_section[len - 3] = '\0';
            printf("\nSection: [%s]\n", current_section);
            continue;
        }
        
        // Parse key-value pairs
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");
        
        if (key != NULL && value != NULL) {
            // Trim whitespace
            while (*key == ' ') key++;
            while (*value == ' ') value++;
            
            char *end = key + strlen(key) - 1;
            while (end > key && *end == ' ') {
                *end = '\0';
                end--;
            }
            
            end = value + strlen(value) - 1;
            while (end > value && *end == ' ') {
                *end = '\0';
                end--;
            }
            
            printf("  %s = %s\n", key, value);
            
            // Example of using the parsed values
            if (strcmp(current_section, "Security") == 0) {
                if (strcmp(key, "max_login_attempts") == 0) {
                    int max_attempts = atoi(value);
                    printf("    (Using max_login_attempts = %d for security policy)\n", max_attempts);
                }
                else if (strcmp(key, "password_min_length") == 0) {
                    int min_length = atoi(value);
                    printf("    (Using password_min_length = %d for password policy)\n", min_length);
                }
            }
        }
    }
    
    // Close the file
    fclose(config_file);
    
    // Security considerations for configuration files
    printf("\nSecurity considerations for configuration files:\n");
    printf("1. Don't store sensitive information (passwords, keys) in plain text\n");
    printf("2. Validate all configuration values before use\n");
    printf("3. Use appropriate file permissions\n");
    printf("4. Consider encrypting sensitive configuration files\n");
    printf("5. Implement secure defaults if configuration is missing\n");
}

int main() {
    printf("=== File Operations in C: Cybersecurity Perspective ===\n");
    
    // Demonstrate basic file operations
    demonstrate_basic_file_operations();
    
    // Demonstrate secure file operations
    demonstrate_secure_file_operations();
    
    // Demonstrate binary file operations
    demonstrate_binary_file_operations();
    
    // Demonstrate secure logging
    demonstrate_secure_logging();
    
    // Demonstrate configuration file parsing
    demonstrate_config_parsing();
    
    printf("\n=== Security Best Practices for File Operations ===\n");
    printf("1. Always check return values from file operations\n");
    printf("2. Use secure file permissions\n");
    printf("3. Validate file paths to prevent path traversal\n");
    printf("4. Properly handle and clean up temporary files\n");
    printf("5. Be cautious with user-supplied filenames\n");
    printf("6. Don't store sensitive information in plain text\n");
    printf("7. Implement proper error handling\n");
    printf("8. Use secure logging practices\n");
    printf("9. Validate configuration values before use\n");
    printf("10. Consider file encryption for sensitive data\n");
    
    return 0;
}

