/**
 * File Integrity Checker
 * 
 * This program demonstrates a simple file integrity checking system
 * using checksums to detect unauthorized modifications.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple checksum calculation (not cryptographically secure)
unsigned int calculate_checksum(FILE *file) {
    unsigned int checksum = 0;
    int ch;

    // Reset file position to beginning
    fseek(file, 0, SEEK_SET);

    while ((ch = fgetc(file)) != EOF) {
        checksum = ((checksum << 5) + checksum) + ch; // Simple hash function
    }

    return checksum;
}

// Save checksum to a file
void save_checksum(const char *filename, unsigned int checksum) {
    char checksum_file[256];
    snprintf(checksum_file, sizeof(checksum_file), "%s.checksum", filename);

    FILE *cf = fopen(checksum_file, "w");
    if (!cf) {
        printf("Error: Cannot create checksum file %s\n", checksum_file);
        return;
    }

    fprintf(cf, "%u", checksum);
    fclose(cf);
    printf("Checksum saved to %s\n", checksum_file);
}

// Read saved checksum from file
int read_checksum(const char *filename, unsigned int *checksum) {
    char checksum_file[256];
    snprintf(checksum_file, sizeof(checksum_file), "%s.checksum", filename);

    FILE *cf = fopen(checksum_file, "r");
    if (!cf) {
        printf("Error: Checksum file not found\n");
        return 0;
    }

    if (fscanf(cf, "%u", checksum) != 1) {
        printf("Error: Invalid checksum file format\n");
        fclose(cf);
        return 0;
    }

    fclose(cf);
    return 1;
}

// Compute checksum for a file
void compute_checksum(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return;
    }

    unsigned int checksum = calculate_checksum(file);
    printf("Checksum for %s: %u\n", filename, checksum);

    save_checksum(filename, checksum);
    fclose(file);
}

// Verify file integrity using saved checksum
void verify_integrity(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return;
    }

    // Calculate current checksum
    unsigned int current_checksum = calculate_checksum(file);

    // Read saved checksum
    unsigned int saved_checksum;
    if (!read_checksum(filename, &saved_checksum)) {
        fclose(file);
        return;
    }

    // Compare checksums
    if (current_checksum == saved_checksum) {
        printf("Verification successful: File integrity maintained\n");
    } else {
        printf("Verification failed: File has been modified!\n");
        printf("Saved checksum: %u\n", saved_checksum);
        printf("Current checksum: %u\n", current_checksum);
    }

    fclose(file);
}

// Create a test file with specified content
void create_test_file(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error: Cannot create test file %s\n", filename);
        return;
    }

    fprintf(file, "%s", content);
    fclose(file);
    printf("Created test file: %s\n", filename);
}

// Modify a test file
void modify_test_file(const char *filename, const char *new_content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error: Cannot open test file %s\n", filename);
        return;
    }

    fprintf(file, "%s", new_content);
    fclose(file);
    printf("Modified test file: %s\n", filename);
}

int main() {
    printf("=== File Integrity Checker ===\n");

    const char *test_filename = "test_file.txt";
    const char *original_content = "This is a test file for integrity checking.\n"
                              "It contains sensitive information that should not be modified.\n"
                              "Any unauthorized changes will be detected.";

    const char *modified_content = "This is a test file for integrity checking.\n"
                              "It contains sensitive information that should not be modified.\n"
                              "This line has been tampered with!";

    // Create a test file
    create_test_file(test_filename, original_content);

    // Compute initial checksum
    printf("\nComputing initial checksum...\n");
    compute_checksum(test_filename);

    // Verify integrity (should pass)
    printf("\nVerifying file integrity (should pass)...\n");
    verify_integrity(test_filename);

    // Modify the file
    printf("\nModifying the file...\n");
    modify_test_file(test_filename, modified_content);

    // Verify integrity again (should fail)
    printf("\nVerifying file integrity (should fail)...\n");
    verify_integrity(test_filename);

    printf("\n=== Security Applications ===\n");
    printf("1. Detect unauthorized file modifications\n");
    printf("2. Verify software integrity before execution\n");
    printf("3. Ensure configuration files haven't been tampered with\n");
    printf("4. Monitor critical system files\n");
    printf("5. Validate downloaded files\n");

    printf("\nNote: For real security applications, use cryptographically secure hash functions\n");
    printf("like SHA-256 instead of the simple checksum used in this example.\n");

    return 0;
}

