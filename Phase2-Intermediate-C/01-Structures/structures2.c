/**
* @file structures.c
* @brief Demonstrates structures and custom data types in C with security applications
* 
* This file explores the concept of structures in C, which allow grouping related
* data of different types into a single unit. It demonstrates how to define, initialize,
* and use structures in the context of security-related applications, including:
*   - Security event logging
*   - User account management
*   - Vulnerability tracking
* 
* Structures are fundamental to organizing complex data in C programs and form the
* basis for object-oriented programming concepts in C.
* 
* Compilation (MSYS2/MinGW):
* gcc structures.c -o structures.exe
* 
* Learning Objectives:
* - Understand structure declaration and initialization
* - Learn how to access and modify structure members
* - Understand passing structures to functions (by value vs. by reference)
* - Learn about typedef for creating type aliases
* - Understand arrays of structures
* - Learn security-focused applications of structures
*/

#include <stdio.h>
#include <string.h>
#include <time.h>

/**
* @brief Structure for a security event
* 
* This structure represents a security-related event in a system,
* containing all relevant information about the event including
* identification, timing, source, and description.
* 
* Memory usage: ~300 bytes per instance (varies by compiler/platform)
*/
struct SecurityEvent {
    int event_id;                // Unique identifier for the event
    char event_type[50];         // Type of security event (e.g., "Login Attempt", "File Access")
    char username[30];           // Username associated with the event
    char source_ip[16];          // Source IP address (IPv4 format: xxx.xxx.xxx.xxx)
    time_t timestamp;            // Time when the event occurred (Unix timestamp)
    int severity;                // Severity level (1-5, with 5 being most severe)
    char description[200];       // Detailed description of the event
};

/**
* @brief Structure for a user account
* 
* This structure represents a user account in a security system,
* containing authentication information, access control data,
* and account status tracking.
* 
* Memory usage: ~150 bytes per instance (varies by compiler/platform)
*/
struct UserAccount {
    int user_id;                 // Unique identifier for the user
    char username[30];           // Username for login
    char password_hash[64];      // Hashed password (never store plaintext!)
    int access_level;            // Access level (1-5, with 5 being highest)
    time_t last_login;           // Time of last login (Unix timestamp)
    int login_attempts;          // Number of failed login attempts
    int account_locked;          // Flag to indicate if account is locked (0=unlocked, 1=locked)
};

/**
* @brief Initializes a security event structure with provided values
* 
* This function safely initializes all fields of a SecurityEvent structure,
* including setting the current timestamp and ensuring all strings are
* properly null-terminated to prevent buffer overflow vulnerabilities.
* 
* @param event Pointer to the SecurityEvent structure to initialize
* @param id Unique identifier for the event
* @param type Type of security event (e.g., "Login Attempt")
* @param user Username associated with the event
* @param ip Source IP address
* @param severity Severity level (1-5, clamped to this range)
* @param desc Detailed description of the event
* 
* @note This function demonstrates defensive programming by:
*       - Using strncpy with explicit null termination for safe string copying
*       - Performing bounds checking on numeric values
*       - Using a pointer parameter to modify the structure directly
*/
void init_security_event(struct SecurityEvent *event, int id, const char *type, 
                         const char *user, const char *ip, int severity, const char *desc) {
    // Set the event ID
    event->event_id = id; // (*event).event_id = id;  // Alternative syntax using dereference operator
    
    // Copy strings with bounds checking to prevent buffer overflow
    strncpy(event->event_type, type, sizeof(event->event_type) - 1);
    event->event_type[sizeof(event->event_type) - 1] = '\0';  // Ensure null termination
    
    strncpy(event->username, user, sizeof(event->username) - 1);
    event->username[sizeof(event->username) - 1] = '\0';
    
    strncpy(event->source_ip, ip, sizeof(event->source_ip) - 1);
    event->source_ip[sizeof(event->source_ip) - 1] = '\0';
    
    strncpy(event->description, desc, sizeof(event->description) - 1);
    event->description[sizeof(event->description) - 1] = '\0';
    
    // Set the timestamp to current time
    event->timestamp = time(NULL);
    
    // Set severity (with bounds checking)
    event->severity = (severity < 1) ? 1 : ((severity > 5) ? 5 : severity);
}

/**
* @brief Displays the contents of a security event structure
* 
* This function formats and prints all fields of a SecurityEvent structure
* in a human-readable format, including converting the timestamp to a
* readable date/time string.
* 
* @param event Pointer to the SecurityEvent structure to display
* 
* @note This function uses the const qualifier to indicate that it
*       will not modify the structure, demonstrating good practice
*       for functions that only read data.
*/
void display_security_event(const struct SecurityEvent *event) {
    // Convert timestamp to readable format
    char time_str[30];
    struct tm *timeinfo = localtime(&event->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Print event details in a formatted way
    printf("=== Security Event #%d ===\n", event->event_id);
    printf("Type: %s\n", event->event_type);
    printf("User: %s\n", event->username);
    printf("Source IP: %s\n", event->source_ip);
    printf("Time: %s\n", time_str);
    printf("Severity: %d/5\n", event->severity);
    printf("Description: %s\n", event->description);
}

/**
* @brief Initializes a user account structure with provided values
* 
* This function safely initializes the fields of a UserAccount structure,
* ensuring all strings are properly null-terminated and numeric values
* are within valid ranges.
* 
* @param user Pointer to the UserAccount structure to initialize
* @param id Unique identifier for the user
* @param username Username for login
* @param password_hash Hashed password (should never be plaintext)
* @param access_level Access level (1-5, clamped to this range)
* 
* @note In a real-world application:
*       - Password hashing would be done with a secure algorithm (e.g., bcrypt, Argon2)
*       - A salt would be stored alongside the hash
*       - Additional security measures like 2FA might be implemented
*/
void init_user_account(struct UserAccount *user, int id, const char *username, 
                      const char *password_hash, int access_level) {
    // Set user ID 
    // (*user).user_id = id;  // Alternative syntax using dereference operator
    // user->user_id = id;    // Preferred syntax using arrow operator
    user->user_id = id;
    
    // Copy strings with bounds checking to prevent buffer overflow
    strncpy(user->username, username, sizeof(user->username) - 1);
    user->username[sizeof(user->username) - 1] = '\0';
    
    strncpy(user->password_hash, password_hash, sizeof(user->password_hash) - 1);
    user->password_hash[sizeof(user->password_hash) - 1] = '\0';
    
    // Set access level with bounds checking
    user->access_level = (access_level < 1) ? 1 : ((access_level > 5) ? 5 : access_level);
    
    // Initialize other fields
    user->last_login = 0;  // No login yet
    user->login_attempts = 0;
    user->account_locked = 0;  // Account is not locked
}

/**
* @brief Simulates a login attempt for a user account
* 
* This function simulates the process of attempting to log in with a user account,
* checking if the account is locked, verifying the password hash, and updating
* the account status based on the result.
* 
* @param user Pointer to the UserAccount structure
* @param password_hash Hash of the attempted password
* @return int 1 if login successful, 0 if failed
* 
* @note This demonstrates how structures can be used to maintain state
*       across function calls (the login_attempts and account_locked fields
*       are updated based on previous values).
*/
int attempt_login(struct UserAccount *user, const char *password_hash) {
    // In a real system, you would hash the provided password and compare hashes
    // For this example, we're comparing hash strings directly
    
    // Check if account is locked
    if (user->account_locked) {
        printf("Login failed: Account is locked\n");
        return 0;  // Login failed
    }
    
    // Compare password hashes
    if (strcmp(user->password_hash, password_hash) == 0) {
        // Successful login
        printf("Login successful for user: %s\n", user->username);
        user->last_login = time(NULL);  // Update last login time
        user->login_attempts = 0;  // Reset failed login attempts
        return 1;  // Login successful
    } else {
        // Failed login
        user->login_attempts++;
        printf("Login failed for user: %s (Attempt %d)\n", user->username, user->login_attempts);
        
        // Lock account after 3 failed attempts
        if (user->login_attempts >= 3) {
            user->account_locked = 1;
            printf("Account locked due to multiple failed login attempts\n");
        }
        
        return 0;  // Login failed
    }
}

/**
* @brief Displays the contents of a user account structure
* 
* This function formats and prints the fields of a UserAccount structure
* in a human-readable format, including converting the last login timestamp
* to a readable date/time string.
* 
* @param user Pointer to the UserAccount structure to display
*/
void display_user_account(const struct UserAccount *user) {
    // Convert timestamp to readable format (if user has logged in before)
    char time_str[30] = "Never";
    if (user->last_login != 0) {
        struct tm *timeinfo = localtime(&user->last_login);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    }
    
    // Print user account details
    printf("=== User Account #%d ===\n", user->user_id);
    printf("Username: %s\n", user->username);
    printf("Access Level: %d/5\n", user->access_level);
    printf("Last Login: %s\n", time_str);
    printf("Failed Login Attempts: %d\n", user->login_attempts);
    printf("Account Status: %s\n", user->account_locked ? "LOCKED" : "Active");
}

/**
* @brief Structure for a security vulnerability (using typedef)
* 
* This structure represents a security vulnerability, containing
* identification, risk assessment, and remediation information.
* 
* The typedef keyword creates an alias "Vulnerability" for this structure type,
* allowing it to be used without the "struct" keyword.
* 
* Memory usage: ~370 bytes per instance (varies by compiler/platform)
*/
typedef struct {
    char name[50];               // Name of the vulnerability
    char cve_id[20];             // Common Vulnerabilities and Exposures ID
    int risk_score;              // Risk score (0-100)
    char affected_systems[100];  // Systems affected by this vulnerability
    char remediation[200];       // Steps to remediate the vulnerability
} Vulnerability;

/**
* @brief Initializes a vulnerability structure with provided values
* 
* This function safely initializes all fields of a Vulnerability structure,
* ensuring all strings are properly null-terminated and numeric values
* are within valid ranges.
* 
* @param vuln Pointer to the Vulnerability structure to initialize
* @param name Name of the vulnerability
* @param cve CVE ID of the vulnerability
* @param risk Risk score (0-100, clamped to this range)
* @param systems Description of affected systems
* @param remediation Steps to remediate the vulnerability
* 
* @note This function demonstrates the use of a typedef'd structure,
*       which is accessed the same way as a regular structure.
*/
void init_vulnerability(Vulnerability *vuln, const char *name, const char *cve, 
                        int risk, const char *systems, const char *remediation) {
    // Copy strings with bounds checking
    strncpy(vuln->name, name, sizeof(vuln->name) - 1);
    vuln->name[sizeof(vuln->name) - 1] = '\0';
    
    strncpy(vuln->cve_id, cve, sizeof(vuln->cve_id) - 1);
    vuln->cve_id[sizeof(vuln->cve_id) - 1] = '\0';
    
    strncpy(vuln->affected_systems, systems, sizeof(vuln->affected_systems) - 1);
    vuln->affected_systems[sizeof(vuln->affected_systems) - 1] = '\0';
    
    strncpy(vuln->remediation, remediation, sizeof(vuln->remediation) - 1);
    vuln->remediation[sizeof(vuln->remediation) - 1] = '\0';
    
    // Set risk score with bounds checking
    vuln->risk_score = (risk < 0) ? 0 : ((risk > 100) ? 100 : risk);
}

/**
* @brief Displays the contents of a vulnerability structure
* 
* This function formats and prints the fields of a Vulnerability structure
* in a human-readable format.
* 
* @param vuln Pointer to the Vulnerability structure to display
*/
void display_vulnerability(const Vulnerability *vuln) {
    printf("=== Vulnerability: %s ===\n", vuln->name);
    printf("CVE ID: %s\n", vuln->cve_id);
    printf("Risk Score: %d/100\n", vuln->risk_score);
    printf("Affected Systems: %s\n", vuln->affected_systems);
    printf("Remediation: %s\n", vuln->remediation);
}

/**
* @brief Main function demonstrating structure usage
* 
* This function demonstrates the creation, initialization, and usage of
* various structures defined in this program, including:
* - Individual structure instances
* - Arrays of structures
* - Structure manipulation through functions
* 
* @return int Exit status (0 for successful execution)
*/
int main() {
    printf("=== Structures and Custom Data Types for Security ===\n\n");
    
    // Create and initialize a security event
    struct SecurityEvent event;
    init_security_event(&event, 1001, "Failed Login", "admin", "192.168.1.100", 
                        4, "Multiple failed login attempts from unusual IP");
    
    // Display the security event
    printf("Security Event Example:\n");
    display_security_event(&event);
    
    // Create and initialize a user account
    struct UserAccount user;
    // Note: In a real system, you would use a proper hashing algorithm with salt
    // This is an MD5 hash of "password" - NOT secure for real applications!
    init_user_account(&user, 101, "admin", "5f4dcc3b5aa765d61d8327deb882cf99", 5);
    
    printf("\nUser Account Example:\n");
    display_user_account(&user);
    
    // Simulate login attempts
    printf("\nSimulating login attempts:\n");
    // Incorrect password
    attempt_login(&user, "wrong_hash");
    attempt_login(&user, "another_wrong_hash");
    
    // Display user account after failed attempts
    printf("\nUser account after failed attempts:\n");
    display_user_account(&user);
    
    // Create and initialize a vulnerability using typedef
    Vulnerability vuln;
    init_vulnerability(&vuln, "Log4Shell", "CVE-2021-44228", 
                      96, "Java applications using Log4j 2.0-2.14.1", 
                      "Update to Log4j 2.15.0 or later, or implement mitigation measures");
    
    printf("\nVulnerability Example:\n");
    display_vulnerability(&vuln);
    
    // Array of structures
    printf("\nArray of Security Events Example:\n");
    struct SecurityEvent event_log[3];
    
    init_security_event(&event_log[0], 1001, "Failed Login", "admin", "192.168.1.100", 
                        4, "Multiple failed login attempts from unusual IP");
    
    init_security_event(&event_log[1], 1002, "File Access", "user1", "192.168.1.105", 
                        3, "Unauthorized attempt to access sensitive file");
    
    init_security_event(&event_log[2], 1003, "Configuration Change", "system", "localhost", 
                        5, "Critical security configuration modified");
    
    // Display all events in the log
    for (int i = 0; i < 3; i++) {
        display_security_event(&event_log[i]);
        printf("\n");
    }
    
    return 0;
}

/**
* Additional Notes on C Structures:
* 
* 1. Memory Layout:
*    - Structure members are stored in contiguous memory locations
*    - The compiler may add padding between members for alignment
*    - The sizeof operator can be used to determine the total size of a structure
* 
* 2. Structure Access:
*    - The dot operator (.) is used to access members of a structure variable
*    - The arrow operator (->) is used to access members of a structure pointer
*    - Example: event.event_id vs. event->event_id
* 
* 3. Structure Assignment:
*    - Structures can be assigned to each other with the = operator
*    - This creates a copy of all members (deep copy)
*    - Example: struct SecurityEvent event2 = event1;
* 
* 4. Structure Comparison:
*    - Structures cannot be directly compared with == or !=
*    - Members must be compared individually
*    - Example: if (event1.event_id == event2.event_id && strcmp(event1.username, event2.username) == 0)
* 
* 5. Structure Padding and Packing:
*    - The compiler may add padding between structure members for alignment
*    - This can be controlled with #pragma pack directives or attributes
*    - Example: #pragma pack(1) // Pack structures with no padding
* 
* 6. Nested Structures:
*    - Structures can contain other structures as members
*    - Example: struct Address { ... }; struct Person { struct Address home_address; ... };
* 
* 7. Self-Referential Structures:
*    - Structures can contain pointers to their own type
*    - This is the basis for linked lists, trees, and other data structures
*    - Example: struct Node { int data; struct Node* next; };
* 
* 8. Structure Memory Management:
*    - Stack-allocated structures are automatically freed when they go out of scope
*    - Heap-allocated structures (using malloc/calloc) must be explicitly freed
*    - Example: struct SecurityEvent* event_ptr = malloc(sizeof(struct SecurityEvent)); ... free(event_ptr);
* 
* 9. Typedef vs. struct:
*    - typedef creates an alias for a type, allowing it to be used without the struct keyword
*    - This is a matter of style and preference
*    - Example: typedef struct { ... } Person; vs. struct Person { ... };
* 
* 10. Security Considerations:
*     - Always initialize all structure members to prevent information leakage
*     - Use secure string handling to prevent buffer overflows
*     - Validate all input before storing in structure members
*     - Clear sensitive data (like passwords) when no longer needed
*/

