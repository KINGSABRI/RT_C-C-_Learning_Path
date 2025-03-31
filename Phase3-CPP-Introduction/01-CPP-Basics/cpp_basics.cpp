#include <iostream>
#include <string>
#include <vector>
#include <memory>

/**
 * Introduction to C++ with a security focus
 * This program demonstrates basic C++ concepts including:
 * - Classes and objects
 * - Inheritance
 * - Polymorphism
 * - Encapsulation
 * - Memory management with smart pointers
 */

// Forward declarations
class User;
class SecurityLog;

/**
 * SecurityLevel enum - defines different security clearance levels
 * Using enum class (C++11 feature) for type safety
 */
enum class SecurityLevel {
    PUBLIC = 0,     // Public information, accessible to all
    CONFIDENTIAL,   // Confidential information, limited access
    SECRET,         // Secret information, very restricted access
    TOP_SECRET      // Top secret information, highest restriction
};

/**
 * Convert SecurityLevel enum to string for display
 * 
 * @param level The security level to convert
 * @return String representation of the security level
 */
std::string securityLevelToString(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::PUBLIC:
            return "PUBLIC";
        case SecurityLevel::CONFIDENTIAL:
            return "CONFIDENTIAL";
        case SecurityLevel::SECRET:
            return "SECRET";
        case SecurityLevel::TOP_SECRET:
            return "TOP_SECRET";
        default:
            return "UNKNOWN";
    }
}

/**
 * SecurityEvent class - base class for all security events
 * Demonstrates encapsulation by keeping data members private
 */
class SecurityEvent {
private:
    // Private data members (encapsulation)
    static int nextEventId;  // Static member to generate unique IDs
    int eventId;             // Unique identifier for this event
    std::string timestamp;   // When the event occurred
    SecurityLevel level;     // Security level of this event
    std::string description; // Description of the event

public:
    // Constructor
    SecurityEvent(const std::string& timestamp, 
                 SecurityLevel level, 
                 const std::string& description)
        : eventId(nextEventId++),
          timestamp(timestamp),
          level(level),
          description(description) {
        // Constructor body (can be empty when using initializer list)
        std::cout << "SecurityEvent created: ID=" << eventId << std::endl;
    }
    
    // Virtual destructor (important for polymorphism)
    virtual ~SecurityEvent() {
        std::cout << "SecurityEvent destroyed: ID=" << eventId << std::endl;
    }
    
    // Getters (accessor methods)
    int getEventId() const { return eventId; }
    std::string getTimestamp() const { return timestamp; }
    SecurityLevel getSecurityLevel() const { return level; }
    std::string getDescription() const { return description; }
    
    // Virtual method for polymorphism
    virtual void logEvent() const {
        std::cout << "Security Event [" << eventId << "] at " << timestamp << std::endl;
        std::cout << "Level: " << securityLevelToString(level) << std::endl;
        std::cout << "Description: " << description << std::endl;
    }
    
    // Static method to get the next event ID
    static int getNextEventId() {
        return nextEventId;
    }
};

// Initialize static member
int SecurityEvent::nextEventId = 1000;

/**
 * AuthenticationEvent class - derived from SecurityEvent
 * Demonstrates inheritance and polymorphism
 */
class AuthenticationEvent : public SecurityEvent {
private:
    std::string username;    // User involved in the authentication
    bool success;            // Whether authentication was successful
    std::string ipAddress;   // IP address of the authentication attempt

public:
    // Constructor
    AuthenticationEvent(const std::string& timestamp,
                       SecurityLevel level,
                       const std::string& description,
                       const std::string& username,
                       bool success,
                       const std::string& ipAddress)
        : SecurityEvent(timestamp, level, description),
          username(username),
          success(success),
          ipAddress(ipAddress) {
        // Constructor body
        std::cout << "AuthenticationEvent created for user: " << username << std::endl;
    }
    
    // Destructor
    ~AuthenticationEvent() override {
        std::cout << "AuthenticationEvent destroyed for user: " << username << std::endl;
    }
    
    // Getters
    std::string getUsername() const { return username; }
    bool isSuccess() const { return success; }
    std::string getIpAddress() const { return ipAddress; }
    
    // Override the base class method (polymorphism)
    void logEvent() const override {
        // Call the base class method first
        SecurityEvent::logEvent();
        
        // Add specialized information
        std::cout << "Authentication " << (success ? "succeeded" : "failed") << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "IP Address: " << ipAddress << std::endl;
    }
};

/**
 * DataAccessEvent class - derived from SecurityEvent
 * Demonstrates another example of inheritance and polymorphism
 */
class DataAccessEvent : public SecurityEvent {
private:
    std::string resourceName;  // Resource that was accessed
    std::string accessType;    // Type of access (read, write, delete)
    std::string userId;        // User who accessed the resource

public:
    // Constructor
    DataAccessEvent(const std::string& timestamp,
                   SecurityLevel level,
                   const std::string& description,
                   const std::string& resourceName,
                   const std::string& accessType,
                   const std::string& userId)
        : SecurityEvent(timestamp, level, description),
          resourceName(resourceName),
          accessType(accessType),
          userId(userId) {
        // Constructor body
        std::cout << "DataAccessEvent created for resource: " << resourceName << std::endl;
    }
    
    // Destructor
    ~DataAccessEvent() override {
        std::cout << "DataAccessEvent destroyed for resource: " << resourceName << std::endl;
    }
    
    // Getters
    std::string getResourceName() const { return resourceName; }
    std::string getAccessType() const { return accessType; }
    std::string getUserId() const { return userId; }
    
    // Override the base class method (polymorphism)
    void logEvent() const override {
        // Call the base class method first
        SecurityEvent::logEvent();
        
        // Add specialized information
        std::cout << "Resource: " << resourceName << std::endl;
        std::cout << "Access Type: " << accessType << std::endl;
        std::cout << "User ID: " << userId << std::endl;
    }
};

/**
 * User class - represents a system user
 */
class User {
private:
    int userId;
    std::string username;
    std::string passwordHash;  // Never store plain text passwords!
    SecurityLevel clearanceLevel;
    bool active;

public:
    // Constructor
    User(int userId, 
         const std::string& username, 
         const std::string& passwordHash,
         SecurityLevel clearanceLevel)
        : userId(userId),
          username(username),
          passwordHash(passwordHash),
          clearanceLevel(clearanceLevel),
          active(true) {
        std::cout << "User created: " << username << std::endl;
    }
    
    // Destructor
    ~User() {
        std::cout << "User destroyed: " << username << std::endl;
    }
    
    // Getters
    int getUserId() const { return userId; }
    std::string getUsername() const { return username; }
    SecurityLevel getClearanceLevel() const { return clearanceLevel; }
    bool isActive() const { return active; }
    
    // Methods
    void deactivate() {
        active = false;
        std::cout << "User " << username << " has been deactivated" << std::endl;
    }
    
    void activate() {
        active = true;
        std::cout << "User " << username << " has been activated" << std::endl;
    }
    
    bool hasAccess(SecurityLevel requiredLevel) const {
        // Check if user has sufficient clearance
        return active && static_cast<int>(clearanceLevel) >= static_cast<int>(requiredLevel);
    }
    
    // Method to verify password (simplified)
    bool verifyPassword(const std::string& passwordAttempt) const {
        // In a real system, you would hash the password attempt and compare hashes
        // This is a simplified example
        return passwordHash == passwordAttempt;
    }
};

/**
 * SecurityLog class - manages a collection of security events
 * Demonstrates container usage and smart pointers
 */
class SecurityLog {
private:
    // Use a vector to store smart pointers to SecurityEvent objects
    std::vector<std::shared_ptr<SecurityEvent>> events;
    std::string logName;

public:
    // Constructor
    explicit SecurityLog(const std::string& logName) : logName(logName) {
        std::cout << "SecurityLog created: " << logName << std::endl;
    }
    
    // Destructor
    ~SecurityLog() {
        std::cout << "SecurityLog destroyed: " << logName << std::endl;
        // No need to manually delete events - shared_ptr handles cleanup
    }
    
    // Add an event to the log
    void addEvent(std::shared_ptr<SecurityEvent> event) {
        events.push_back(event);
        std::cout << "Event added to log: " << logName << std::endl;
    }
    
    // Print all events in the log
    void printAllEvents() const {
        std::cout << "\n=== Security Log: " << logName << " ===\n";
        std::cout << "Total events: " << events.size() << std::endl;
        
        for (const auto& event : events) {
            std::cout << "\n";
            event->logEvent();
        }
        
        std::cout << "=== End of Log ===\n";
    }
    
    // Filter events by security level
    void printEventsByLevel(SecurityLevel level) const {
        std::cout << "\n=== Security Log: " << logName << " (Filtered by Level: " 
                  << securityLevelToString(level) << ") ===\n";
        
        int count = 0;
        for (const auto& event : events) {
            if (event->getSecurityLevel() == level) {
                std::cout << "\n";
                event->logEvent();
                count++;
            }
        }
        
        std::cout << "Total matching events: " << count << std::endl;
        std::cout << "=== End of Filtered Log ===\n";
    }
};

/**
 * SecuritySystem class - main class that ties everything together
 * Demonstrates composition and dependency relationships
 */
class SecuritySystem {
private:
    std::vector<std::shared_ptr<User>> users;
    std::shared_ptr<SecurityLog> systemLog;
    
public:
    // Constructor
    SecuritySystem() : systemLog(std::make_shared<SecurityLog>("System Security Log")) {
        std::cout << "Security System initialized" << std::endl;
    }
    
    // Destructor
    ~SecuritySystem() {
        std::cout << "Security System shutdown" << std::endl;
    }
    
    // Add a user to the system
    void addUser(std::shared_ptr<User> user) {
        users.push_back(user);
        std::cout << "User added to security system: " << user->getUsername() << std::endl;
    }
    
    // Log an event
    void logEvent(std::shared_ptr<SecurityEvent> event) {
        systemLog->addEvent(event);
    }
    
    // Authenticate a user
    bool authenticateUser(const std::string& username, const std::string& password) {
        // Get current timestamp (simplified)
        std::string timestamp = "2023-01-01 12:00:00";
        
        // Find the user
        for (const auto& user : users) {
            if (user->getUsername() == username) {
                bool success = user->verifyPassword(password);
                
                // Create an authentication event
                auto event = std::make_shared<AuthenticationEvent>(
                    timestamp,
                    success ? SecurityLevel::CONFIDENTIAL : SecurityLevel::SECRET,
                    success ? "Successful login" : "Failed login attempt",
                    username,
                    success,
                    "192.168.1.100"  // Simulated IP address
                );
                
                // Log the event
                logEvent(event);
                
                return success;
            }
        }
        
        // User not found
        auto event = std::make_shared<AuthenticationEvent>(
            timestamp,
            SecurityLevel::SECRET,
            "Login attempt for non-existent user",
            username,
            false,
            "192.168.1.100"  // Simulated IP address
        );
        
        logEvent(event);
        return false;
    }
    
    // Access a resource
    bool accessResource(const std::string& username, const std::string& resourceName, 
                       const std::string& accessType, SecurityLevel resourceLevel) {
        // Get current timestamp (simplified)
        std::string timestamp = "2023-01-01 12:30:00";
        
        // Find the user
        for (const auto& user : users) {
            if (user->getUsername() == username) {
                bool hasAccess = user->hasAccess(resourceLevel);
                
                // Create a data access event
                auto event = std::make_shared<DataAccessEvent>(
                    timestamp,
                    hasAccess ? SecurityLevel::CONFIDENTIAL : SecurityLevel::SECRET,
                    hasAccess ? "Resource access granted" : "Resource access denied",
                    resourceName,
                    accessType,
                    username
                );
                
                // Log the event
                logEvent(event);
                
                return hasAccess;
            }
        }
        
        // User not found
        auto event = std::make_shared<DataAccessEvent>(
            timestamp,
            SecurityLevel::SECRET,
            "Resource access attempt by non-existent user",
            resourceName,
            accessType,
            username
        );
        
        logEvent(event);
        return false;
    }
    
    // Print all security logs
    void printSecurityLogs() const {
        systemLog->printAllEvents();
    }
    
    // Print security logs filtered by level
    void printSecurityLogsByLevel(SecurityLevel level) const {
        systemLog->printEventsByLevel(level);
    }
};

/**
 * Main function to demonstrate C++ concepts
 */
int main() {
    std::cout << "=== C++ Security System Demonstration ===\n\n";
    
    // Create a security system
    SecuritySystem securitySystem;
    
    // Create users with different clearance levels
    auto admin = std::make_shared<User>(
        1, "admin", "admin_hash", SecurityLevel::TOP_SECRET
    );
    
    auto analyst = std::make_shared<User>(
        2, "analyst", "analyst_hash", SecurityLevel::SECRET
    );
    
    auto user = std::make_shared<User>(
        3, "user", "user_hash", SecurityLevel::CONFIDENTIAL
    );
    
    auto guest = std::make_shared<User>(
        4, "guest", "guest_hash", SecurityLevel::PUBLIC
    );
    
    // Add users to the system
    securitySystem.addUser(admin);
    securitySystem.addUser(analyst);
    securitySystem.addUser(user);
    securitySystem.addUser(guest);
    
    std::cout << "\n=== Authentication Tests ===\n";
    
    // Test authentication
    securitySystem.authenticateUser("admin", "admin_hash");     // Should succeed
    securitySystem.authenticateUser("analyst", "wrong_hash");   // Should fail
    securitySystem.authenticateUser("unknown", "any_hash");     // User doesn't exist
    
    std::cout << "\n=== Resource Access Tests ===\n";
    
    // Test resource access
    securitySystem.accessResource("admin", "top_secret_file.txt", "read", SecurityLevel::TOP_SECRET);
    securitySystem.accessResource("analyst", "secret_file.txt", "write", SecurityLevel::SECRET);
    securitySystem.accessResource("user", "secret_file.txt", "read", SecurityLevel::SECRET);
    securitySystem.accessResource("guest", "public_file.txt", "read", SecurityLevel::PUBLIC);
    
    // Print all security logs
    securitySystem.printSecurityLogs();
    
    // Print filtered logs
    securitySystem.printSecurityLogsByLevel(SecurityLevel::SECRET);
    
    std::cout << "\n=== End of Demonstration ===\n";
    
    // All cleanup is handled automatically by smart pointers
    return 0;
}

