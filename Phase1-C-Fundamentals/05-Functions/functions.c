/**
* @file functions.c
* @brief Demonstrates functions in C
* 
* This file explores the concept of functions in C, including function
* declaration, definition, parameters, return values, and recursion.
* It also covers pass-by-value vs. pass-by-reference (using pointers) and
* arrays as function parameters.
* 
* Compilation (MSYS2/MinGW):
* gcc functions.c -o functions.exe
* 
* Learning Objectives:
* - Understand function declaration and definition
* - Learn about function parameters and return values
* - Understand pass-by-value vs. pass-by-reference (using pointers)
* - Learn about arrays as function parameters
* - Understand recursion
* - Learn about function pointers
*/

#include <stdio.h>
#include <string.h>

// Function declarations (prototypes)
void greet(void);
void greet_person(const char* name);
int add(int a, int b);
double add_doubles(double a, double b);
void modify_value(int value);
void modify_pointer(int* value);
int factorial(int n);
void print_array(int arr[], int size);
int sum_array(const int arr[], int size);
void default_params(int a, int b, int c);
int square(int x);
void function_pointer_demo(void);

// Function pointer type definition
typedef int (*MathOperation)(int, int);
int perform_operation(int a, int b, MathOperation operation);
int multiply(int a, int b);
int subtract(int a, int b);

int main() {
    printf("=== C Functions ===\n\n");
    
    // ===== Basic Function Calls =====
    printf("--- Basic Function Calls ---\n");
    
    // Call function with no parameters and no return value
    greet();
    
    // Call function with a parameter
    greet_person("Alice");
    
    // Call function with parameters and return value
    int sum = add(5, 3);
    printf("5 + 3 = %d\n", sum);
    
    // Call function with different parameter types
    double double_sum = add_doubles(3.5, 2.7);
    printf("3.5 + 2.7 = %lf\n", double_sum);
    
    printf("\n");
    
    // ===== Pass by Value vs. Pass by Reference =====
    printf("--- Pass by Value vs. Pass by Reference ---\n");
    
    int original_value = 10;
    printf("Original value: %d\n", original_value);
    
    // Pass by value
    modify_value(original_value);
    printf("After pass by value: %d\n", original_value);
    
    // Pass by reference (using pointers)
    modify_pointer(&original_value);
    printf("After pass by reference (pointer): %d\n", original_value);
    
    printf("\n");
    
    // ===== Arrays as Function Parameters =====
    printf("--- Arrays as Function Parameters ---\n");
    
    int numbers[] = {1, 2, 3, 4, 5};
    int array_size = sizeof(numbers) / sizeof(numbers[0]);
    
    printf("Array contents: ");
    print_array(numbers, array_size);
    
    int array_sum = sum_array(numbers, array_size);
    printf("Sum of array elements: %d\n", array_sum);
    
    printf("\n");
    
    // ===== Recursion =====
    printf("--- Recursion ---\n");
    
    int n = 5;
    int fact = factorial(n);
    printf("%d! = %d\n", n, fact);
    
    printf("\n");
    
    // ===== Default Parameters (C doesn't support this directly) =====
    printf("--- Default Parameters (Simulated) ---\n");
    
    // Call with all parameters specified
    default_params(10, 20, 30);
    
    // In C, we can't have true default parameters, but we can simulate them
    // by checking for special values inside the function
    
    printf("\n");
    
    // ===== Inline Function (C99 and later) =====
    printf("--- Inline Function ---\n");
    
    // Call inline function
    int squared = square(5);
    printf("5 squared = %d\n", squared);
    
    printf("\n");
    
    // ===== Function Pointers =====
    printf("--- Function Pointers ---\n");
    
    function_pointer_demo();
    
    return 0;
}

/**
* @brief Simple greeting function with no parameters
*/
void greet(void) {
    printf("Hello, World!\n");
}

/**
* @brief Greeting function that takes a name parameter
* 
* @param name The name to include in the greeting
*/
void greet_person(const char* name) {
    printf("Hello, %s!\n", name);
}

/**
* @brief Adds two integers
* 
* @param a First integer
* @param b Second integer
* @return int Sum of the two integers
*/
int add(int a, int b) {
    return a + b;
}

/**
* @brief Adds two doubles
* 
* @param a First double
* @param b Second double
* @return double Sum of the two doubles
*/
double add_doubles(double a, double b) {
    return a + b;
}

/**
* @brief Demonstrates pass by value (creates a copy of the parameter)
* 
* @param value The value to modify (a copy is created)
*/
void modify_value(int value) {
    value = value * 2;  // This only modifies the local copy
    printf("Inside modify_value: %d\n", value);
}

/**
* @brief Demonstrates pass by reference using pointers
* 
* @param value Pointer to the value to modify
*/
void modify_pointer(int* value) {
    *value = *value * 2;  // This modifies the value at the address
    printf("Inside modify_pointer: %d\n", *value);
}

/**
* @brief Calculates the factorial of a number using recursion
* 
* @param n The number to calculate factorial for
* @return int The factorial of n
*/
int factorial(int n) {
    // Base case
    if (n <= 1) {
        return 1;
    }
    
    // Recursive case
    return n * factorial(n - 1);
}

/**
* @brief Prints the contents of an array
* 
* @param arr The array to print
* @param size The size of the array
*/
void print_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

/**
* @brief Calculates the sum of elements in an array
* 
* @param arr The array to sum
* @param size The size of the array
* @return int The sum of all elements
*/
int sum_array(const int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

/**
* @brief Simulates default parameters (C doesn't support this directly)
* 
* @param a First parameter
* @param b Second parameter
* @param c Third parameter
*/
void default_params(int a, int b, int c) {
    // In a real implementation, we might check for special values
    // to simulate default parameters
    printf("a = %d, b = %d, c = %d\n", a, b, c);
}

/**
* @brief Inline function to calculate the square of a number
* 
* The 'inline' keyword suggests to the compiler to insert the function's code
* directly at the call site, potentially improving performance for small functions
* by avoiding the overhead of a function call.
* 
* Note: 'inline' is a C99 feature and may not be supported in older C compilers.
* 
* @param x The number to square
* @return int The square of x
*/
inline int square(int x) {
    return x * x;
}

/**
* @brief Multiplies two integers
* 
* @param a First integer
* @param b Second integer
* @return int Product of the two integers
*/
int multiply(int a, int b) {
    return a * b;
}

/**
* @brief Subtracts two integers
* 
* @param a First integer
* @param b Second integer
* @return int Difference of the two integers
*/
int subtract(int a, int b) {
    return a - b;
}

/**
* @brief Performs a mathematical operation using a function pointer
* 
* @param a First integer
* @param b Second integer
* @param operation Function pointer to the operation to perform
* @return int Result of the operation
*/
int perform_operation(int a, int b, MathOperation operation) {
    return operation(a, b);
}

/**
* @brief Demonstrates the use of function pointers
*/
void function_pointer_demo(void) {
    int a = 10, b = 5;
    
    // Using function pointers
    int (*add_ptr)(int, int) = add;
    int (*multiply_ptr)(int, int) = multiply;
    int (*subtract_ptr)(int, int) = subtract;
    
    printf("Using function pointers:\n");
    printf("%d + %d = %d\n", a, b, add_ptr(a, b));
    printf("%d * %d = %d\n", a, b, multiply_ptr(a, b));
    printf("%d - %d = %d\n", a, b, subtract_ptr(a, b));
    
    // Using the perform_operation function
    printf("\nUsing perform_operation function:\n");
    printf("%d + %d = %d\n", a, b, perform_operation(a, b, add));
    printf("%d * %d = %d\n", a, b, perform_operation(a, b  a, b, perform_operation(a, b, add));
    printf("%d * %d = %d\n", a, b, perform_operation(a, b, multiply));
    printf("%d - %d = %d\n", a, b, perform_operation(a, b, subtract));
    
    // Array of function pointers
    printf("\nUsing an array of function pointers:\n");
    MathOperation operations[] = {add, multiply, subtract};
    const char* op_names[] = {"Addition", "Multiplication", "Subtraction"};
    
    for (int i = 0; i < 3; i++) {
        printf("%s: %d %s %d = %d\n", 
               op_names[i], 
               a, 
               i == 0 ? "+" : (i == 1 ? "*" : "-"), 
               b, 
               operations[i](a, b));
    }
}

/**
* Additional Notes:
* 
* 1. Function Declaration vs. Definition:
*    - Declaration (prototype): Tells the compiler about the function's name, return type, and parameters
*    - Definition: Contains the actual implementation of the function
* 
* 2. Function Parameters:
*    - Pass by value: Creates a copy of the argument
*    - Pass by reference: In C, this is achieved using pointers
* 
* 3. Function Overloading:
*    - C does not support function overloading (unlike C++)
*    - Each function must have a unique name
* 
* 4. Recursion:
*    - A function that calls itself
*    - Must have a base case to prevent infinite recursion
* 
* 5. Default Parameters:
*    - C does not support default parameters (unlike C++)
*    - Can be simulated by checking for special values inside the function
* 
* 6. Inline Functions:
*    - Suggestion to the compiler to insert the function code at the call site
*    - May improve performance for small, frequently called functions
*    - The compiler may ignore the inline suggestion
*    - Supported in C99 and later
* 
* 7. Function Pointers:
*    - Allow functions to be passed as arguments to other functions
*    - Enable implementation of callbacks and dynamic behavior
*    - Syntax can be complex: return_type (*pointer_name)(parameter_types)
* 
* 8. Function Best Practices:
*    - Keep functions small and focused on a single task
*    - Use meaningful function names
*    - Document parameters and return values
*    - Consider const-correctness for pointers to prevent unintended modifications
*/

