/**
 * Structures and Custom Data Types for Security Applications
 * 
 * This program demonstrates how to create and use structures and custom
 * data types for security-related applications.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

// Define a structure for a security event
struct SecurityEvent {
    int event_id;                // Unique identifier for the event
    char event_type[50];         // Type of security event (e.g., "Login Attempt", "File Access")
    char username[30];           // Username associated with the event
    char source_ip[16];          // Source IP address
    time_t timestamp;            // Time when the event occurred
    int severity;                // Severity level (1-5, with 5 being most severe)
    char description[200];       // Detailed description of the event
};

// Define a structure for a user account
struct UserAccount {
    int user_id;                 // Unique identifier for the user
    char username[30];           // Username for login
    char password_hash[64];      // Hashed password (never store plaintext!)
    int access_level;            // Access level (1-5, with 5 being highest)
    time_t last_login;           // Time of last login
    int login_attempts;          // Number of failed login attempts
    int account_locked;          // Flag to indicate if account is locked (0=unlocked, 1=locked)
};

// Function to initialize a security event
void init_security_event(struct SecurityEvent *event, int id, const char *type, 
                         const char *user, const char *ip, int severity, const char *desc) {
    // Set the event ID
    event->event_id = id;
    
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

// Function to display a security event
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

// Function to initialize a user account
void init_user_account(struct UserAccount *user, int id, const char *username, 
                      const char *password_hash, int access_level) {
    // Set user ID
    user->user_id = id;
    
    // Copy strings with bounds checking
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

// Function to simulate a login attempt
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

// Function to display user account information
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

// Typedef example - creating an alias for a structure type
typedef struct {
    char name[50];           // Name of the vulnerability
    char cve_id[20];         // Common Vulnerabilities and Exposures ID
    int risk_score;          // Risk score (0-100)
    char affected_systems[100];  // Systems affected by this vulnerability
    char remediation[200];   // Steps to remediate the vulnerability
} Vulnerability;

// Function to initialize a vulnerability
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

// Function to display vulnerability information
void display_vulnerability(const Vulnerability *vuln) {
    printf("=== Vulnerability: %s ===\n", vuln->name);
    printf("CVE ID: %s\n", vuln->cve_id);
    printf("Risk Score: %d/100\n", vuln->risk_score);
    printf("Affected Systems: %s\n", vuln->affected_systems);
    printf("Remediation: %s\n", vuln->remediation);
}

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

