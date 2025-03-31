/**
 * Control Flow in C - Cybersecurity Perspective
 * 
 * This program demonstrates various control flow constructs in C
 * and their security implications.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// Function to demonstrate if-else statements
void demonstrateIfElse() {
    printf("\n=== If-Else Statements ===\n");
    
    int securityLevel = 3;  // 1=Low, 2=Medium, 3=High
    
    printf("Current security level: %d\n", securityLevel);
    
    // Simple if statement
    if (securityLevel >= 3) {
        printf("High security mode activated\n");
    }
    
    // If-else statement
    if (securityLevel == 1) {
        printf("Security level: Low\n");
    } else if (securityLevel == 2) {
        printf("Security level: Medium\n");
    } else if (securityLevel == 3) {
        printf("Security level: High\n");
    } else {
        printf("Invalid security level\n");
    }
    
    // Nested if statements
    if (securityLevel > 1) {
        printf("Enhanced security features enabled:\n");
        
        if (securityLevel >= 3) {
            printf("- Two-factor authentication\n");
            printf("- Encryption\n");
            printf("- Advanced logging\n");
        } else {
            printf("- Basic authentication\n");
            printf("- Simple logging\n");
        }
    }
}

// Function to demonstrate switch statements
void demonstrateSwitch() {
    printf("\n=== Switch Statements ===\n");
    
    int errorCode = 403;
    
    printf("Error code: %d\n", errorCode);
    
    // Switch statement
    switch (errorCode) {
        case 200:
            printf("Status: OK\n");
            break;
        case 401:
            printf("Status: Unauthorized\n");
            printf("Security action: Prompt for authentication\n");
            break;
        case 403:
            printf("Status: Forbidden\n");
            printf("Security action: Log access attempt\n");
            printf("Security action: Alert administrator\n");
            break;
        case 404:
            printf("Status: Not Found\n");
            break;
        case 500:
            printf("Status: Internal Server Error\n");
            printf("Security action: Check logs for potential issues\n");
            break;
        default:
            printf("Status: Unknown error code\n");
            printf("Security action: Log for investigation\n");
    }
}

// Function to demonstrate while loops
void demonstrateWhileLoops() {
    printf("\n=== While Loops ===\n");
    
    // Simple while loop
    printf("Simple while loop:\n");
    int attempt = 1;
    int maxAttempts = 3;
    
    while (attempt <= maxAttempts) {
        printf("Login attempt %d of %d\n", attempt, maxAttempts);
        attempt++;
    }
    
    // Do-while loop
    printf("\nDo-while loop:\n");
    int option;
    
    do {
        printf("Security Options:\n");
        printf("1. Enable firewall\n");
        printf("2. Update passwords\n");
        printf("3. Scan for vulnerabilities\n");
        printf("0. Exit\n");
        printf("Select option (0-3): ");
        
        // Simulating user input
        option = 2;  // For demonstration, we're using a fixed value
        printf("%d\n", option);
        
        // Process the option
        switch (option) {
            case 1:
                printf("Firewall enabled\n");
                break;
            case 2:
                printf("Passwords updated\n");
                break;
            case 3:
                printf("Scanning for vulnerabilities...\n");
                break;
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid option\n");
        }
        
        // For demonstration purposes, we'll break after one iteration
        break;
        
    } while (option != 0);
}

// Function to demonstrate for loops
void demonstrateForLoops() {
    printf("\n=== For Loops ===\n");
    
    // Simple for loop
    printf("Simple for loop:\n");
    for (int i = 1; i <= 3; i++) {
        printf("Checking security module %d\n", i);
    }
    
    // For loop with array
    printf("\nFor loop with array:\n");
    char* vulnerabilities[] = {
        "Buffer Overflow",
        "SQL Injection",
        "Cross-Site Scripting",
        "Authentication Bypass"
    };
    
    int numVulnerabilities = sizeof(vulnerabilities) / sizeof(vulnerabilities[0]);
    
    printf("Security Scan Results - Found %d vulnerabilities:\n", numVulnerabilities);
    for (int i = 0; i < numVulnerabilities; i++) {
        printf("%d. %s\n", i + 1, vulnerabilities[i]);
    }
    
    // Nested for loops
    printf("\nNested for loops:\n");
    printf("Scanning network (10.0.0.x):\n");
    
    // Outer loop
    for (int subnet = 0; subnet < 2; subnet++) {
        printf("Subnet 10.0.%d.x:\n", subnet);
        
        // Inner loop - only scan a few IPs for demonstration
        for (int host = 1; host <= 3; host++) {
            printf("  Scanning 10.0.%d.%d\n", subnet, host);
        }
    }
}

// Function to demonstrate break and continue
void demonstrateBreakContinue() {
    printf("\n=== Break and Continue Statements ===\n");
    
    // Break example
    printf("Break example - Intrusion detection:\n");
    int packetCount = 0;
    bool intrusionDetected = false;
    
    for (int i = 1; i <= 10; i++) {
        printf("Analyzing packet %d... ", i);
        
        // Simulate intrusion in packet 5
        if (i == 5) {
            printf("ALERT! Suspicious pattern detected!\n");
            intrusionDetected = true;
            break;  // Exit the loop early
        }
        
        printf("OK\n");
        packetCount++;
    }
    
    printf("Packets analyzed: %d\n", packetCount);
    printf("Intrusion detected: %s\n", intrusionDetected ? "Yes" : "No");
    
    // Continue example
    printf("\nContinue example - Firewall filtering:\n");
    int allowedPackets = 0;
    int blockedPackets = 0;
    
    for (int i = 1; i <= 8; i++) {
        printf("Packet %d from IP 192.168.1.%d: ", i, i * 10);
        
        // Simulate blocked IPs (3 and 6)
        if (i == 3 || i == 6) {
            printf("BLOCKED (Blacklisted IP)\n");
            blockedPackets++;
            continue;  // Skip the rest of the loop body
        }
        
        printf("ALLOWED\n");
        allowedPackets++;
    }
    
    printf("Allowed packets: %d\n", allowedPackets);
    printf("Blocked packets: %d\n", blockedPackets);
}

// Function to validate user input (basic security check)
bool validateInput(char* input) {
    // Check if input is too long (potential buffer overflow)
    if (strlen(input) > 20) {
        return false;
    }
    
    // Check for suspicious characters
    for (int i = 0; input[i] != '\0'; i++) {
        if (input[i] == ';' || input[i] == '|' || input[i] == '`') {
            return false;  // Potential command injection
        }
    }
    
    return true;
}

// Function to demonstrate security implications
void demonstrateSecurityImplications() {
    printf("\n=== Security Implications of Control Flow ===\n");
    
    // 1. Input validation
    printf("\n1. Input Validation:\n");
    char* validInput = "username";
    char* invalidInput1 = "admin; rm -rf /";  // Command injection attempt
    char* invalidInput2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";  // Too long
    
    printf("Validating: '%s' - %s\n", validInput, 
           validateInput(validInput) ? "VALID" : "INVALID");
    printf("Validating: '%s' - %s\n", invalidInput1, 
           validateInput(invalidInput1) ? "VALID" : "INVALID");
    printf("Validating: '%s' - %s\n", invalidInput2, 
           validateInput(invalidInput2) ? "VALID" : "INVALID");
    
    // 2. Authentication with rate limiting
    printf("\n2. Authentication with Rate Limiting:\n");
    bool authenticated = false;
    int loginAttempts = 0;
    int maxLoginAttempts = 3;
    
    // Simulated login attempts
    char* passwords[] = {"wrong1", "wrong2", "correct", "wrong3"};
    
    for (int i = 0; i < 4; i++) {
        if (loginAttempts >= maxLoginAttempts) {
            printf("Account locked due to too many failed attempts!\n");
            break;
        }
        
        printf("Login attempt with password: %s\n", passwords[i]);
        
        // Check if password is correct
        if (strcmp(passwords[i], "correct") == 0) {
            printf("Login successful!\n");
            authenticated = true;
            break;
        } else {
            printf("Login failed!\n");
            loginAttempts++;
        }
    }
    
    printf("Authentication status: %s\n", authenticated ? "Authenticated" : "Not authenticated");
    printf("Login attempts: %d\n", loginAttempts);
    
    // 3. Authorization checks
    printf("\n3. Authorization Checks:\n");
    int userRole = 2;  // 1=Admin, 2=User, 3=Guest
    
    printf("User role: %d\n", userRole);
    
    switch (userRole) {
        case 1:  // Admin
            printf("Access granted to: System Configuration\n");
            printf("Access granted to: User Management\n");
            printf("Access granted to: Content Management\n");
            break;
        case 2:  // User
            printf("Access denied to: System Configuration\n");
            printf("Access denied to: User Management\n");
            printf("Access granted to: Content Management\n");
            break;
        case 3:  // Guest
            printf("Access denied to: System Configuration\n");
            printf("Access denied to: User Management\n");
            printf("Access denied to: Content Management\n");
            printf("Access granted to: Public Content\n");
            break;
        default:
            printf("Unknown role - No access granted\n");
    }
}

int main() {
    printf("=== Control Flow in C: Cybersecurity Perspective ===\n");
    
    // Demonstrate different control flow constructs
    demonstrateIfElse();
    demonstrateSwitch();
    demonstrateWhileLoops();
    demonstrateForLoops();
    demonstrateBreakContinue();
    
    // Demonstrate security implications
    demonstrateSecurityImplications();
    
    printf("\n=== Security Best Practices ===\n");
    printf("1. Always validate user input\n");
    printf("2. Implement proper authentication and authorization\n");
    printf("3. Use rate limiting for sensitive operations\n");
    printf("4. Be cautious with early termination (break/return)\n");
    printf("5. Avoid complex nested conditions when possible\n");
    printf("6. Ensure all control paths are properly tested\n");
    
    return 0;
}

