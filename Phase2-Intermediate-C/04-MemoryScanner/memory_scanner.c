/**
 * Memory Scanner - Cybersecurity Practice Project
 * 
 * This program demonstrates a simple memory scanner that can search
 * for patterns in memory, useful for security analysis and debugging.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Define memory region structure
typedef struct {
    void *start;       // Start address of the memory region
    void *end;         // End address of the memory region
    size_t size;       // Size of the memory region in bytes
    char name[64];     // Name or description of the region
} MemoryRegion;

// Define pattern match result structure
typedef struct {
    void *address;     // Address where the pattern was found
    size_t offset;     // Offset from the start of the region
} MatchResult;

// Define pattern scanner structure
typedef struct {
    MatchResult *results;   // Array of match results
    size_t capacity;        // Maximum number of results that can be stored
    size_t count;           // Current number of results
} PatternScanner;

// Function to initialize a memory region
MemoryRegion* create_memory_region(void *start, size_t size, const char *name) {
    MemoryRegion *region = (MemoryRegion*)malloc(sizeof(MemoryRegion));
    if (region == NULL) {
        return NULL;
    }
    
    region->start = start;
    region->end = (uint8_t*)start + size;
    region->size = size;
    
    strncpy(region->name, name, sizeof(region->name) - 1);
    region->name[sizeof(region->name) - 1] = '\0';  // Ensure null termination
    
    return region;
}

// Function to initialize a pattern scanner
PatternScanner* create_pattern_scanner(size_t max_results) {
    PatternScanner *scanner = (PatternScanner*)malloc(sizeof(PatternScanner));
    if (scanner == NULL) {
        return NULL;
    }
    
    scanner->results = (MatchResult*)malloc(max_results * sizeof(MatchResult));
    if (scanner->results == NULL) {
        free(scanner);
        return NULL;
    }
    
    scanner->capacity = max_results;
    scanner->count = 0;
    
    return scanner;
}

// Function to destroy a pattern scanner
void destroy_pattern_scanner(PatternScanner *scanner) {
    if (scanner != NULL) {
        if (scanner->results != NULL) {
            free(scanner->results);
        }
        free(scanner);
    }
}

// Function to add a match result to the scanner
int add_match_result(PatternScanner *scanner, void *address, size_t offset) {
    if (scanner == NULL || scanner->count >= scanner->capacity) {
        return 0;  // Failed to add result
    }
    
    scanner->results[scanner->count].address = address;
    scanner->results[scanner->count].offset = offset;
    scanner->count++;
    
    return 1;  // Successfully added result
}

// Function to scan memory for a byte pattern
void scan_memory_for_pattern(MemoryRegion *region, const uint8_t *pattern, 
                           size_t pattern_size, PatternScanner *scanner) {
    if (region == NULL || pattern == NULL || pattern_size == 0 || scanner == NULL) {
        return;
    }
    
    uint8_t *current = (uint8_t*)region->start;
    uint8_t *end = (uint8_t*)region->end - pattern_size + 1;
    
    while (current < end) {
        if (memcmp(current, pattern, pattern_size) == 0) {
            // Pattern found
            size_t offset = current - (uint8_t*)region->start;
            add_match_result(scanner, current, offset);
        }
        current++;
    }
}

// Function to scan memory for a string pattern
void scan_memory_for_string(MemoryRegion *region, const char *string, 
                          PatternScanner *scanner) {
    scan_memory_for_pattern(region, (const uint8_t*)string, strlen(string) + 1, scanner);
}

// Function to print match results
void print_match_results(PatternScanner *scanner, MemoryRegion *region) {
    if (scanner == NULL || region == NULL) {
        return;
    }
    
    printf("Found %zu matches in region '%s':\n", scanner->count, region->name);
    
    for (size_t i = 0; i < scanner->count; i++) {
        printf("  Match #%zu: Address %p (Offset: %zu bytes)\n", 
               i + 1, scanner->results[i].address, scanner->results[i].offset);
        
        // Print a few bytes before and after the match for context
        uint8_t *addr = (uint8_t*)scanner->results[i].address;
        printf("  Context: ");
        
        // Print up to 8 bytes before the match
        size_t pre_bytes = (scanner->results[i].offset < 8) ? 
                          scanner->results[i].offset : 8;
        
        for (size_t j = pre_bytes; j > 0; j--) {
            printf("%02X ", addr[-j]);
        }
        
        // Print the first few bytes of the match in a different format
        printf("[");
        size_t match_bytes = (16 - pre_bytes < 8) ? 16 - pre_bytes : 8;
        for (size_t j = 0; j < match_bytes; j++) {
            printf("%02X ", addr[j]);
        }
        printf("]");
        
        printf("\n");
    }
}

// Function to modify memory at a specific address
int modify_memory(void *address, const uint8_t *new_data, size_t data_size) {
    if (address == NULL || new_data == NULL || data_size == 0) {
        return 0;  // Failed to modify memory
    }
    
    // In a real-world scenario, we would need to check memory permissions
    // and potentially change them to allow writing
    
    // Copy the new data to the address
    memcpy(address, new_data, data_size);
    
    return 1;  // Successfully modified memory
}

// Function to demonstrate a buffer overflow vulnerability
void demonstrate_buffer_overflow() {
    printf("\n=== Buffer Overflow Demonstration ===\n");
    
    // Create a structure with a buffer and a control variable
    typedef struct {
        char buffer[16];
        int control_value;
    } VulnerableStruct;
    
    // Initialize the structure
    VulnerableStruct vuln;
    vuln.control_value = 0x12345678;
    
    printf("Before overflow:\n");
    printf("  Control value: 0x%08X\n", vuln.control_value);
    
    // Create a memory region for the structure
    MemoryRegion *region = create_memory_region(&vuln, sizeof(VulnerableStruct), "VulnerableStruct");
    
    // Create a pattern scanner
    PatternScanner *scanner = create_pattern_scanner(10);
    
    // Scan for the control value
    uint32_t pattern = 0x12345678;
    scan_memory_for_pattern(region, (const uint8_t*)&pattern, sizeof(pattern), scanner);
    
    // Print the results
    print_match_results(scanner, region);
    
    // Cause a buffer overflow
    char *large_input = "AAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD";
    printf("\nCausing buffer overflow with input: %s\n", large_input);
    
    // This will overflow the buffer and overwrite the control_value
    strcpy(vuln.buffer, large_input);
    
    printf("After overflow:\n");
    printf("  Control value: 0x%08X\n", vuln.control_value);
    
    // Scan for the new control value (which has been overwritten)
    scanner->count = 0;  // Reset the scanner
    scan_memory_for_pattern(region, (const uint8_t*)&vuln.control_value, sizeof(vuln.control_value), scanner);
    
    // Print the results
    print_match_results(scanner, region);
    
    // Clean up
    destroy_pattern_scanner(scanner);
    free(region);
}

// Function to demonstrate memory scanning and modification
void demonstrate_memory_scanning() {
    printf("\n=== Memory Scanning Demonstration ===\n");
    
    // Create some data to scan
    char *data = strdup("This is a test string with a secret password: P@ssw0rd123!");
    if (data == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    size_t data_size = strlen(data) + 1;
    
    printf("Original data: %s\n", data);
    
    // Create a memory region for the data
    MemoryRegion *region = create_memory_region(data, data_size, "TestData");
    
    // Create a pattern scanner
    PatternScanner *scanner = create_pattern_scanner(10);
    
    // Scan for the password
    printf("\nScanning for 'P@ssw0rd123!'...\n");
    scan_memory_for_string(region, "P@ssw0rd123!", scanner);
    
    // Print the results
    print_match_results(scanner, region);
    
    // Modify the password in memory
    if (scanner->count > 0) {
        printf("\nModifying the password in memory...\n");
        const char *new_password = "Secur3P@ss!";
        modify_memory(scanner->results[0].address, (const uint8_t*)new_password, strlen(new_password) + 1);
        
        printf("Data after modification: %s\n", data);
    }
    
    // Scan for other patterns
    scanner->count = 0;  // Reset the scanner
    printf("\nScanning for 'test'...\n");
    scan_memory_for_string(region, "test", scanner);
    
    // Print the results
    print_match_results(scanner, region);
    
    // Clean up
    destroy_pattern_scanner(scanner);
    free(region);
    free(data);
}

// Function to demonstrate memory protection bypass
void demonstrate_memory_protection() {
    printf("\n=== Memory Protection Demonstration ===\n");
    
    // In a real-world scenario, this would involve changing memory protections
    // using platform-specific APIs like VirtualProtect on Windows or mprotect on Unix
    
    printf("Memory protection demonstration:\n");
    printf("1. In real applications, memory can be marked as read-only or non-executable\n");
    printf("2. Attackers may try to bypass these protections to inject code\n");
    printf("3. Memory scanners can identify areas where protections are missing\n");
    printf("4. This requires platform-specific code not included in this example\n");
}

int main() {
    printf("=== Memory Scanner: Cybersecurity Practice Project ===\n");
    
    // Demonstrate memory scanning
    demonstrate_memory_scanning();
    
    // Demonstrate buffer overflow
    demonstrate_buffer_overflow();
    
    // Demonstrate memory protection
    demonstrate_memory_protection();
    
    printf("\n=== Security Implications ===\n");
    printf("1. Memory scanning can be used to find sensitive data in memory\n");
    printf("2. Buffer overflows can corrupt memory and potentially lead to code execution\n");
    printf("3. Memory protection mechanisms can be bypassed in some cases\n");
    printf("4. Understanding these techniques is important for security professionals\n");
    
    printf("\n=== Defensive Measures ===\n");
    printf("1. Use secure coding practices to prevent buffer overflows\n");
    printf("2. Implement proper memory protection mechanisms\n");
    printf("3. Don't store sensitive data in memory longer than necessary\n");
    printf("4. Use memory encryption for sensitive data\n");
    printf("5. Employ address space layout randomization (ASLR)\n");
    
    return 0;
}

