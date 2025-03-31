/**
 * Hello Security - Introduction to C Programming for Cybersecurity
 * 
 * This program demonstrates basic C syntax and structure with a security focus.
 * It shows how to print messages, use variables, and implement a simple function.
 */

#include <stdio.h>  // Standard input/output library
#include <stdlib.h> // Standard library
#include <time.h>   // Time functions

// Function declaration (prototype)
void printSecurityTip(int tipNumber);

int main() {
    // Print welcome message
    printf("=== Cybersecurity C Programming ===\n\n");
    
    // Variables
    char name[50] = "Security Student"; // String (character array)
    int year = 2023;                    // Integer
    float version = 1.0;                // Floating-point number
    
    // Print program information
    printf("Welcome, %s!\n", name);
    printf("Program: Introduction to C for Security\n");
    printf("Version: %.1f (%d)\n\n", version, year);
    
    // Get current time
    time_t currentTime;
    time(&currentTime);
    
    // Print current time
    printf("Current time: %s", ctime(&currentTime));
    printf("This information could be useful for logging security events.\n\n");
    
    // Generate a random number for selecting a security tip
    srand((unsigned int)time(NULL)); // Seed the random number generator
    int randomTip = rand() % 5 + 1;  // Random number between 1 and 5
    
    // Print a random security tip
    printf("Security Tip of the Day (#%d):\n", randomTip);
    printSecurityTip(randomTip);
    
    // Exit the program
    printf("\nEnd of program. Exiting securely...\n");
    return 0; // Return success code
}

/**
 * Function to print a security tip based on the tip number
 * 
 * @param tipNumber The number of the tip to print (1-5)
 */
void printSecurityTip(int tipNumber) {
    // Switch statement to select the appropriate tip
    switch (tipNumber) {
        case 1:
            printf("Always validate user input to prevent buffer overflows and injection attacks.");
            break;
        case 2:
            printf("Use secure memory functions like strncpy() instead of strcpy() to prevent buffer overflows.");
            break;
        case 3:
            printf("Check return values from functions to detect and handle errors properly.");
            break;
        case 4:
            printf("Initialize variables before use to avoid undefined behavior and potential security issues.");
            break;
        case 5:
            printf("Free allocated memory to prevent memory leaks that could lead to denial of service.");
            break;
        default:
            printf("Unknown tip number.");
    }
}

