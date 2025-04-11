/**
* @file arrays.c
* @brief Demonstrates arrays in C
* 
* This file explores the concept of arrays in C, including declaration,
* initialization, accessing elements, multi-dimensional arrays, and common
* array operations. It also covers the relationship between arrays and pointers.
* 
* Compilation (MSYS2/MinGW):
* gcc arrays.c -o arrays.exe
* 
* Learning Objectives:
* - Understand array declaration and initialization
* - Learn how to access and modify array elements
* - Understand multi-dimensional arrays
* - Learn about common array operations
* - Understand the relationship between arrays and pointers
*/

#include <stdio.h>
#include <string.h>  // For string functions

int main() {
    printf("=== C Arrays ===\n\n");
    
    // ===== Array Declaration and Initialization =====
    printf("--- Array Declaration and Initialization ---\n");
    
    // Declare and initialize an array
    int numbers[5] = {10, 20, 30, 40, 50};
    
    // Declare an array without initialization
    int uninitialized[5];  // Contains garbage values
    
    // Initialize with fewer values than the array size
    int partial[5] = {1, 2, 3};  // Remaining elements are initialized to 0
    
    // Let the compiler determine the size
    int auto_sized[] = {5, 10, 15, 20, 25};  // Size is determined by the initializer
    
    // Initialize all elements to zero
    int zeros[5] = {0};  // All elements are initialized to 0
    
    // Print the arrays
    printf("numbers array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    printf("partial array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", partial[i]);
    }
    printf("\n");
    
    printf("auto_sized array: ");
    int auto_size = sizeof(auto_sized) / sizeof(auto_sized[0]);
    for (int i = 0; i < auto_size; i++) {
        printf("%d ", auto_sized[i]);
    }
    printf("\n");
    
    printf("zeros array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", zeros[i]);
    }
    printf("\n");
    
    printf("\n");
    
    // ===== Accessing and Modifying Array Elements =====
    printf("--- Accessing and Modifying Array Elements ---\n");
    
    // Access array elements
    printf("Third element of numbers: %d\n", numbers[2]);  // Arrays are 0-indexed
    
    // Modify array elements
    numbers[2] = 35;
    printf("Modified third element: %d\n", numbers[2]);
    
    // Array bounds
    printf("Array bounds in C are not checked at runtime!\n");
    printf("Accessing out-of-bounds elements can lead to undefined behavior.\n");
    
    printf("\n");
    
    // ===== Character Arrays and Strings =====
    printf("--- Character Arrays and Strings ---\n");
    
    // Character array (string)
    char greeting[6] = {'H', 'e', 'l', 'l', 'o', '\0'};  // Null-terminated
    
    // String literal
    char message[] = "Hello, World!";  // Compiler adds the null terminator
    
    // Print strings
    printf("greeting: %s\n", greeting);
    printf("message: %s\n", message);
    
    // String length
    printf("Length of message: %zu\n", strlen(message));
    
    // String functions
    char str1[20] = "Hello";
    char str2[] = ", World!";
    
    // String concatenation
    strcat(str1, str2);
    printf("Concatenated string: %s\n", str1);
    
    // String copy
    char str3[20];
    strcpy(str3, "C Programming");
    printf("Copied string: %s\n", str3);
    
    // String comparison
    int compare_result = strcmp("apple", "banana");
    printf("Comparison result: %d (negative means first string comes before second)\n", compare_result);
    
    printf("\n");
    
    // ===== Multi-dimensional Arrays =====
    printf("--- Multi-dimensional Arrays ---\n");
    
    // 2D array
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    // Print 2D array
    printf("2D array (matrix):\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%2d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // 3D array
    int cube[2][2][2] = {
        {{1, 2}, {3, 4}},
        {{5, 6}, {7, 8}}
    };
    
    // Print 3D array
    printf("\n3D array (cube):\n");
    for (int i = 0; i < 2; i++) {
        printf("Layer %d:\n", i + 1);
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 2; k++) {
                printf("%d ", cube[i][j][k]);
            }
            printf("\n");
        }
    }
    
    printf("\n");
    
    // ===== Arrays and Pointers =====
    printf("--- Arrays and Pointers ---\n");
    
    int values[5] = {10, 20, 30, 40, 50};
    int* ptr = values;  // Array name decays to a pointer to its first element
    
    // Access array elements using pointer
    printf("First element using array notation: %d\n", values[0]);
    printf("First element using pointer notation: %d\n", *ptr);
    
    // Pointer arithmetic
    printf("Second element using pointer arithmetic: %d\n", *(ptr + 1));
    printf("Third element using pointer arithmetic: %d\n", *(ptr + 2));
    
    // Iterate through array using pointers
    printf("Array elements using pointer iteration: ");
    for (int* p = values; p < values + 5; p++) {
        printf("%d ", *p);
    }
    printf("\n");
    
    // Relationship between array indexing and pointer arithmetic
    printf("Array indexing is equivalent to pointer arithmetic:\n");
    printf("values[3] = %d, *(values + 3) = %d\n", values[3], *(values + 3));
    
    printf("\n");
    
    // ===== Common Array Operations =====
    printf("--- Common Array Operations ---\n");
    
    int data[10] = {64, 34, 25, 12, 22, 11, 90, 75, 45, 50};
    int data_size = sizeof(data) / sizeof(data[0]);
    
    // Find the sum of array elements
    int sum = 0;
    for (int i = 0; i < data_size; i++) {
        sum += data[i];
    }
    printf("Sum of array elements: %d\n", sum);
    
    // Find the average of array elements
    double average = (double)sum / data_size;
    printf("Average of array elements: %.2f\n", average);
    
    // Find the maximum element
    int max = data[0];
    for (int i = 1; i < data_size; i++) {
        if (data[i] > max) {
            max = data[i];
        }
    }
    printf("Maximum element: %d\n", max);
    
    // Find the minimum element
    int min = data[0];
    for (int i = 1; i < data_size; i++) {
        if (data[i] < min) {
            min = data[i];
        }
    }
    printf("Minimum element: %d\n", min);
    
    // Reverse the array
    printf("Original array: ");
    for (int i = 0; i < data_size; i++) {
        printf("%d ", data[i]);
    }
    printf("\n");
    
    // Perform the reversal
    for (int i = 0; i < data_size / 2; i++) {
        int temp = data[i];
        data[i] = data[data_size - 1 - i];
        data[data_size - 1 - i] = temp;
    }
    
    printf("Reversed array: ");
    for (int i = 0; i < data_size; i++) {
        printf("%d ", data[i]);
    }
    printf("\n");
    
    return 0;
}

/**
* Additional Notes:
* 
* 1. Array Declaration:
*    - Format: type array_name[size];
*    - Size must be a constant expression in C89/C90
*    - C99 and later allow variable-length arrays (VLAs)
* 
* 2. Array Initialization:
*    - Can be done at declaration time
*    - If partially initialized, remaining elements are set to 0
*    - If size is omitted, it's determined by the initializer
* 
* 3. Array Access:
*    - Zero-indexed (first element is at index 0)
*    - Bounds checking is not performed in C
*    - Accessing out-of-bounds elements leads to undefined behavior
* 
* 4. Character Arrays and Strings:
*    - Strings in C are character arrays terminated by a null character ('\0')
*    - String literals are enclosed in double quotes
*    - String functions are provided in <string.h>
* 
* 5. Multi-dimensional Arrays:
*    - Can have any number of dimensions
*    - Stored in row-major order (rightmost index varies fastest)
*    - Can be initialized with nested braces
* 
* 6. Arrays and Pointers:
*    - Array name decays to a pointer to its first element in most contexts
*    - Array indexing (arr[i]) is equivalent to pointer arithmetic (*(arr + i))
*    - Arrays are not assignable (cannot use arr1 = arr2)
* 
* 7. Common Array Operations:
*    - Traversal: Visit each element
*    - Search: Find a specific element
*    - Update: Modify elements
*    - Insertion/Deletion: Add or remove elements (requires manual shifting in C)
*    - Sorting: Arrange elements in a specific order
* 
* 8. Memory Considerations:
*    - Arrays are stored in contiguous memory locations
*    - Size of an array (in bytes) = number of elements * size of each element
*    - Stack-allocated arrays have a limited size (consider using dynamic allocation for large arrays)
*/

