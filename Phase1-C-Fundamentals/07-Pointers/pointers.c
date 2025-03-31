/**
 * Pointers in C - Cybersecurity Perspective
 * 
 * This program demonstrates pointers in C with a focus on
 * security implications and best practices.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to demonstrate basic pointer operations
void demonstrate_basic_pointers() {
    printf("\n=== Basic Pointer Operations ===\n");
    
    // Declare and initialize variables
    int value = 42;
    int *ptr = &value;  // Pointer to value
    
    // Print variable and pointer information
    printf("Variable value: %d\n", value);
    printf("Variable address: %p\n", (void*)&value);
    printf("Pointer value (address it points to): %p\n", (void*)ptr);
    printf("Dereferenced pointer (value at the address): %d\n", *ptr);
    
    // Modify value through pointer
    *ptr = 100;
    printf("\nAfter modification through pointer:\n");
    printf("Variable value: %d\n", value);
    
    // Null pointer
    int *null_ptr = NULL;
    printf("\nNull pointer: %p\n", (void*)null_ptr);
    
    // Demonstrate null pointer check
    if (null_ptr != NULL) {
        // This code won't execute
        printf("This won't print because the pointer is NULL\n");
        // *null_ptr = 10;  // This would cause a segmentation fault
    } else {
        printf("Null pointer detected - avoiding dereferencing\n");
    }
    
    // Pointer to pointer
    int **ptr_to_ptr = &ptr;
    printf("\nPointer to pointer:\n");
    printf("ptr_to_ptr: %p\n", (void*)ptr_to_ptr);
    printf("*ptr_to_ptr (value of ptr): %p\n", (void*)*ptr_to_ptr);
    printf("**ptr_to_ptr (value of value): %d\n", **ptr_to_ptr);
}

// Function to demonstrate pointer arithmetic
void demonstrate_pointer_arithmetic() {
    printf("\n=== Pointer Arithmetic ===\n");
    
    // Array declaration
    int numbers[5] = {10, 20, 30, 40, 50};
    int *ptr = numbers;  // Pointer to the first element
    
    // Print array using pointer arithmetic
    printf("Array elements using pointer arithmetic:\n");
    for (int i = 0; i < 5; i++) {
        printf("*(ptr + %d) = %d\n", i, *(ptr + i));
    }
    
    // Another way to access array elements with pointers
    printf("\nAlternative pointer notation:\n");
    for (int i = 0; i < 5; i++) {
        printf("ptr[%d] = %d\n", i, ptr[i]);
    }
    
    // Incrementing pointers
    printf("\nIncrementing pointers:\n");
    printf("Initial ptr points to: %d\n", *ptr);
    
    ptr++;  // Move to next element
    printf("After ptr++, ptr points to: %d\n", *ptr);
    
    ptr += 2;  // Move forward by 2 elements
    printf("After ptr += 2, ptr points to: %d\n", *ptr);
    
    ptr--;  // Move back by 1 element
    printf("After ptr--, ptr points to: %d\n", *ptr);
    
    // Pointer comparison
    printf("\nPointer comparison:\n");
    int *start = numbers;
    int *current = numbers + 3;
    
    printf("Difference between pointers: %ld elements\n", current - start);
    
    if (current > start) {
        printf("current pointer is ahead of start pointer\n");
    } else {
        printf("current pointer is behind start pointer\n");
    }
}

// Function to demonstrate dynamic memory allocation
void demonstrate_dynamic_memory() {
    printf("\n=== Dynamic Memory Allocation ===\n");
    
    // Allocate memory for a single integer
    int *single_int = (int*)malloc(sizeof(int));
    
    // Check if allocation was successful
    if (single_int == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Use the allocated memory
    *single_int = 42;
    printf("Dynamically allocated int: %d\n", *single_int);
    
    // Free the memory when done
    free(single_int);
    printf("Memory freed for single int\n");
    
    // Allocate memory for an array of integers
    int size = 5;
    int *int_array = (int*)malloc(size * sizeof(int));
    
    // Check if allocation was successful
    if (int_array == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Initialize the array
    for (int i = 0; i < size; i++) {
        int_array[i] = i * 10;
    }
    
    // Print the array
    printf("\nDynamically allocated array:\n");
    for (int i = 0; i < size; i++) {
        printf("int_array[%d] = %d\n", i, int_array[i]);
    }
    
    // Free the array memory
    free(int_array);
    printf("Memory freed for int array\n");
    
    // Using calloc (allocates and initializes memory to zero)
    int *zeroed_array = (int*)calloc(size, sizeof(int));
    
    // Check if allocation was successful
    if (zeroed_array == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Print the zeroed array
    printf("\nArray allocated with calloc (initialized to zero):\n");
    for (int i = 0; i < size; i++) {
        printf("zeroed_array[%d] = %d\n", i, zeroed_array[i]);
    }
    
    // Resize the array using realloc
    int new_size = 8;
    zeroed_array = (int*)realloc(zeroed_array, new_size * sizeof(int));
    
    // Check if reallocation was successful
    if (zeroed_array == NULL) {
        printf("Memory reallocation failed\n");
        return;
    }
    
    // Initialize the new elements
    for (int i = size; i < new_size; i++) {
        zeroed_array[i] = i * 10;
    }
    
    // Print the resized array
    printf("\nResized array after realloc:\n");
    for (int i = 0; i < new_size; i++) {
        printf("zeroed_array[%d] = %d\n", i, zeroed_array[i]);
    }
    
    // Free the resized array
    free(zeroed_array);
    printf("Memory freed for resized array\n");
}

// Function to demonstrate common pointer errors
void demonstrate_pointer_errors() {
    printf("\n=== Common Pointer Errors ===\n");
    
    // 1. Null pointer dereference
    printf("1. Null Pointer Dereference:\n");
    int *null_ptr = NULL;
    printf("   null_ptr = %p\n", (void*)null_ptr);
    printf("   Dereferencing a null pointer would cause a crash\n");
    // *null_ptr = 10;  // This would cause a segmentation fault
    
    // 2. Uninitialized pointer
    printf("\n2. Uninitialized Pointer:\n");
    int *uninit_ptr;  // Uninitialized pointer
    printf("   uninit_ptr contains a random address: %p\n", (void*)uninit_ptr);
    printf("   Dereferencing an uninitialized pointer is dangerous\n");
    // *uninit_ptr = 20;  // This would likely cause a segmentation fault
    
    // 3. Dangling pointer (use-after-free)
    printf("\n3. Dangling Pointer (Use-After-Free):\n");
    int *dangling_ptr = (int*)malloc(sizeof(int));
    *dangling_ptr = 30;
    printf("   Before free: *dangling_ptr = %d\n", *dangling_ptr);
    
    free(dangling_ptr);  // Free the memory
    printf("   Memory has been freed\n");
    
    // The pointer still holds the address, but the memory is no longer valid
    printf("   dangling_ptr still contains the address: %p\n", (void*)dangling_ptr);
    printf("   Dereferencing a dangling pointer is undefined behavior\n");
    // *dangling_ptr = 40;  // This would cause undefined behavior
    
    // 4. Memory leak
    printf("\n4. Memory Leak:\n");
    int *leak_ptr = (int*)malloc(sizeof(int));
    *leak_ptr = 50;
    printf("   Allocated memory: *leak_ptr = %d\n", *leak_ptr);
    
    // If we don't free leak_ptr and lose the reference to it,
    // the memory will be leaked (not freed until program termination)
    printf("   If we lose the pointer without freeing, we have a memory leak\n");
    
    // Proper cleanup
    free(leak_ptr);
    printf("   Memory properly freed\n");
    
    // 5. Buffer overflow
    printf("\n5. Buffer Overflow:\n");
    int buffer[5] = {1, 2, 3, 4, 5};
    int *buffer_ptr = buffer;
    
    printf("   Buffer size: 5 integers\n");
    printf("   Accessing within bounds: buffer_ptr[4] = %d\n", buffer_ptr[4]);
    
    printf("   Accessing out of bounds can corrupt memory or crash the program\n");
    // buffer_ptr[10] = 100;  // This would write beyond the buffer's bounds
}

// Function to demonstrate function pointers
void demonstrate_function_pointers() {
    printf("\n=== Function Pointers ===\n");
    
    // Define function pointer types
    typedef int (*BinaryOperation)(int, int);
    
    // Functions to be pointed to
    int (*add)(int, int) = [](int a, int b) { return a + b; };
    int (*subtract)(int, int) = [](int a, int b) { return a - b; };
    int (*multiply)(int, int) = [](int a, int b) { return a * b; };
    
    // Array of function pointers
    BinaryOperation operations[3] = {add, subtract, multiply};
    const char* op_names[3] = {"Addition", "Subtraction", "Multiplication"};
    
    // Use function pointers
    int a = 10, b = 5;
    
    for (int i = 0; i < 3; i++) {
        BinaryOperation operation = operations[i];
        int result = operation(a, b);
        printf("%s: %d %s %d = %d\n", 
               op_names[i], a, 
               i == 0 ? "+" : (i == 1 ? "-" : "*"), 
               b, result);
    }
    
    // Function pointer for a security operation
    typedef void (*SecurityCheck)(const char*);
    
    // Security check function
    SecurityCheck check_password = [](const char* password) {
        if (strlen(password) < 8) {
            printf("Password too short (less than 8 characters)\n");
        } else {
            printf("Password length acceptable\n");
        }
    };
    
    // Use the security check function
    printf("\nSecurity check using function pointer:\n");
    check_password("short");
    check_password("secure_password");
}

// Function to demonstrate void pointers
void demonstrate_void_pointers() {
    printf("\n=== Void Pointers ===\n");
    
    // Void pointer can point to any data type
    int int_value = 42;
    float float_value = 3.14f;
    char char_value = 'A';
    
    void *void_ptr;
    
    // Point to an integer
    void_ptr = &int_value;
    printf("Void pointer pointing to int: %d\n", *(int*)void_ptr);
    
    // Point to a float
    void_ptr = &float_value;
    printf("Void pointer pointing to float: %.2f\n", *(float*)void_ptr);
    
    // Point to a char
    void_ptr = &char_value;
    printf("Void pointer pointing to char: %c\n", *(char*)void_ptr);
    
    // Generic memory copy function using void pointers
    void *generic_copy(const void *src, size_t size) {
        void *dest = malloc(size);
        if (dest != NULL) {
            memcpy(dest, src, size);
        }
        return dest;
    }
    
    // Use the generic copy function
    int *int_copy = (int*)generic_copy(&int_value, sizeof(int));
    if (int_copy != NULL) {
        printf("Copied int value: %d\n", *int_copy);
        free(int_copy);
    }
    
    // Security implications
    printf("\nSecurity implications of void pointers:\n");
    printf("1. Type casting can hide type errors\n");
    printf("2. No type checking by the compiler\n");
    printf("3. Can lead to memory corruption if used incorrectly\n");
    printf("4. Useful for generic functions but require careful handling\n");
}

// Function to demonstrate secure pointer usage
void demonstrate_secure_pointer_usage() {
    printf("\n=== Secure Pointer Usage ===\n");
    
    // 1. Always initialize pointers
    int *ptr1 = NULL;  // Initialize to NULL
    printf("1. Always initialize pointers to NULL\n");
    
    // 2. Check for NULL before dereferencing
    if (ptr1 != NULL) {
        // Safe to dereference
        // *ptr1 = 10;
    } else {
        printf("2. Check for NULL before dereferencing\n");
    }
    
    // 3. Proper memory allocation with error checking
    int *ptr2 = (int*)malloc(sizeof(int));
    if (ptr2 == NULL) {
        printf("3. Always check if memory allocation succeeded\n");
        // Handle error
    } else {
        *ptr2 = 20;
        printf("   Memory allocated successfully: %d\n", *ptr2);
    }
    
    // 4. Proper memory deallocation
    free(ptr2);
    ptr2 = NULL;  // Set to NULL after freeing
    printf("4. Set pointers to NULL after freeing\n");
    
    // 5. Avoid pointer arithmetic that goes out of bounds
    int array[5] = {1, 2, 3, 4, 5};
    int *array_ptr = array;
    
    printf("5. Ensure pointer arithmetic stays within bounds\n");
    for (int i = 0; i < 5; i++) {  // Correct bound
        printf("   array_ptr[%d] = %d\n", i, array_ptr[i]);
    }
    
    // 6. Use const for pointers that shouldn't modify data
    const int value = 30;
    const int *const_ptr = &value;  // Pointer to constant int
    
    // *const_ptr = 40;  // This would be a compile error
    printf("6. Use const for pointers that shouldn't modify data: %d\n", *const_ptr);
    
    // 7. Secure string handling
    char source[] = "This is a test string";
    char destination[10];  // Too small for the source
    
    printf("7. Use secure string functions:\n");
    printf("   Source: \"%s\" (length: %zu)\n", source, strlen(source));
    printf("   Destination buffer size: 10 bytes\n");
    
    // Unsafe: strcpy(destination, source);  // Buffer overflow!
    
    // Safe: Use strncpy with explicit null termination
    strncpy(destination, source, sizeof(destination) - 1);
    destination[sizeof(destination) - 1] = '\0';
    
    printf("   After safe copy: \"%s\"\n", destination);
    
    // 8. Clear sensitive data from memory
    char password[] = "secret_password";
    printf("8. Clear sensitive data from memory when no longer needed\n");
    printf("   Before clearing: \"%s\"\n", password);
    
    // Clear the memory
    memset(password, 0, strlen(password));
    printf("   After clearing: \"%s\"\n", password);
}

int main() {
    printf("=== Pointers in C: Cybersecurity Perspective ===\n");
    
    // Demonstrate basic pointer operations
    demonstrate_basic_pointers();
    
    // Demonstrate pointer arithmetic
    demonstrate_pointer_arithmetic();
    
    // Demonstrate dynamic memory allocation
    demonstrate_dynamic_memory();
    
    // Demonstrate common pointer errors
    demonstrate_pointer_errors();
    
    // Demonstrate function pointers
    demonstrate_function_pointers();
    
    // Demonstrate void pointers
    demonstrate_void_pointers();
    
    // Demonstrate secure pointer usage
    demonstrate_secure_pointer_usage();
    
    printf("\n=== Security Best Practices for Pointers ===\n");
    printf("1. Always initialize pointers (preferably to NULL)\n");
    printf("2. Check for NULL before dereferencing\n");
    printf("3. Validate memory allocation success\n");
    printf("4. Free dynamically allocated memory when done\n");
    printf("5. Set pointers to NULL after freeing\n");
    printf("6. Avoid pointer arithmetic that could go out of bounds\n");
    printf("7. Use const for pointers that shouldn't modify data\n");
    printf("8. Use secure string functions (strncpy, strncat, etc.)\n");
    printf("9. Clear sensitive data from memory when no longer needed\n");
    printf("10. Be cautious with void pointers and type casting\n");
    
    return 0;
}

