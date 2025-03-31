#include <iostream>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <algorithm>
#include <string>

/**
 * Basic STL Demonstration
 * 
 * This program demonstrates the fundamental components of the
 * Standard Template Library (STL) with a security focus:
 * - Containers
 * - Algorithms
 * - Iterators
 */

int main() {
    std::cout << "=== STL Basics for Security Applications ===\n\n";
    
    // ===== CONTAINERS =====
    std::cout << "=== STL Containers ===\n";
    
    // Vector - dynamic array
    std::cout << "\n1. Vector (dynamic array):\n";
    std::vector<std::string> securityEvents;
    
    // Add elements
    securityEvents.push_back("Login attempt");
    securityEvents.push_back("File access");
    securityEvents.push_back("Configuration change");
    securityEvents.push_back("Password reset");
    
    // Access elements
    std::cout << "First event: " << securityEvents[0] << std::endl;
    std::cout << "Last event: " << securityEvents.back() << std::endl;
    std::cout << "Number of events: " << securityEvents.size() << std::endl;
    
    // List - doubly linked list
    std::cout << "\n2. List (doubly linked list):\n";
    std::list<std::string> vulnerabilities;
    
    // Add elements
    vulnerabilities.push_back("Buffer overflow");
    vulnerabilities.push_back("SQL injection");
    vulnerabilities.push_front("Cross-site scripting");  // Add to front
    vulnerabilities.push_back("Insecure deserialization");
    
    // Iterate through the list
    std::cout << "Vulnerabilities:" << std::endl;
    for (const auto& vuln : vulnerabilities) {
        std::cout << "  - " << vuln << std::endl;
    }
    
    // Map - key-value pairs
    std::cout << "\n3. Map (key-value pairs):\n";
    std::map<std::string, int> threatLevels;
    
    // Add elements
    threatLevels["Low"] = 1;
    threatLevels["Medium"] = 2;
    threatLevels["High"] = 3;
    threatLevels["Critical"] = 4;
    
    // Access elements
    std::cout << "Threat levels:" << std::endl;
    for (const auto& pair : threatLevels) {
        std::cout << "  " << pair.first << ": " << pair.second << std::endl;
    }
    
    // Check if a key exists
    std::string threatToCheck = "High";
    if (threatLevels.find(threatToCheck) != threatLevels.end()) {
        std::cout << "Threat level '" << threatToCheck << "' exists with value: " 
                  << threatLevels[threatToCheck] << std::endl;
    }
    
    // Set - unique elements
    std::cout << "\n4. Set (unique elements):\n";
    std::set<std::string> blockedIPs;
    
    // Add elements
    blockedIPs.insert("192.168.1.100");
    blocke  blockedIPs;
    
    // Add elements
    blockedIPs.insert("192.168.1.100");
    blockedIPs.insert("10.0.0.5");
    blockedIPs.insert("172.16.0.1");
    blockedIPs.insert("192.168.1.100");  // Duplicate - will be ignored
    
    // Check size and contents
    std::cout << "Number of blocked IPs: " << blockedIPs.size() << std::endl;
    std::cout << "Blocked IPs:" << std::endl;
    for (const auto& ip : blockedIPs) {
        std::cout << "  " << ip << std::endl;
    }
    
    // Check if an IP is blocked
    std::string ipToCheck = "10.0.0.5";
    if (blockedIPs.find(ipToCheck) != blockedIPs.end()) {
        std::cout << "IP " << ipToCheck << " is blocked" << std::endl;
    }
    
    // ===== ALGORITHMS =====
    std::cout << "\n=== STL Algorithms ===\n";
    
    // Find algorithm
    std::cout << "\n1. Find algorithm:\n";
    auto it = std::find(securityEvents.begin(), securityEvents.end(), "File access");
    if (it != securityEvents.end()) {
        std::cout << "Found event: " << *it << " at position " 
                  << (it - securityEvents.begin()) << std::endl;
    }
    
    // Sort algorithm
    std::cout << "\n2. Sort algorithm:\n";
    std::cout << "Events before sorting:" << std::endl;
    for (const auto& event : securityEvents) {
        std::cout << "  " << event << std::endl;
    }
    
    std::sort(securityEvents.begin(), securityEvents.end());
    
    std::cout << "Events after sorting:" << std::endl;
    for (const auto& event : securityEvents) {
        std::cout << "  " << event << std::endl;
    }
    
    // Count algorithm
    std::cout << "\n3. Count algorithm:\n";
    std::vector<int> severityLevels = {1, 3, 2, 1, 4, 3, 5, 1, 2, 3};
    
    int criticalCount = std::count(severityLevels.begin(), severityLevels.end(), 5);
    std::cout << "Number of critical (level 5) events: " << criticalCount << std::endl;
    
    // Count_if algorithm with lambda
    std::cout << "\n4. Count_if algorithm with lambda:\n";
    int highSeverityCount = std::count_if(severityLevels.begin(), severityLevels.end(),
        [](int level) { return level >= 4; });  // Lambda function
    
    std::cout << "Number of high severity events (level 4-5): " << highSeverityCount << std::endl;
    
    // Transform algorithm
    std::cout << "\n5. Transform algorithm:\n";
    std::vector<int> adjustedLevels(severityLevels.size());
    
    // Increase all severity levels by 1 (capped at 5)
    std::transform(severityLevels.begin(), severityLevels.end(), adjustedLevels.begin(),
        [](int level) { return std::min(level + 1, 5); });
    
    std::cout << "Original severity levels: ";
    for (int level : severityLevels) {
        std::cout << level << " ";
    }
    std::cout << std::endl;
    
    std::cout << "Adjusted severity levels: ";
    for (int level : adjustedLevels) {
        std::cout << level << " ";
    }
    std::cout << std::endl;
    
    // ===== SECURITY APPLICATIONS =====
    std::cout << "\n=== STL Security Applications ===\n";
    
    // Password policy checking
    std::cout << "\n1. Password policy checking:\n";
    std::string password = "Passw0rd!";
    
    bool hasUppercase = std::any_of(password.begin(), password.end(), [](char c) { return std::isupper(c); });
    bool hasLowercase = std::any_of(password.begin(), password.end(), [](char c) { return std::islower(c); });
    bool hasDigit = std::any_of(password.begin(), password.end(), [](char c) { return std::isdigit(c); });
    bool hasSpecial = std::any_of(password.begin(), password.end(), 
                                 [](char c) { return !std::isalnum(c); });
    bool isLongEnough = password.length() >= 8;
    
    std::cout << "Password: " << password << std::endl;
    std::cout << "Meets requirements:" << std::endl;
    std::cout << "  Length >= 8: " << (isLongEnough ? "Yes" : "No") << std::endl;
    std::cout << "  Has uppercase: " << (hasUppercase ? "Yes" : "No") << std::endl;
    std::cout << "  Has lowercase: " << (hasLowercase ? "Yes" : "No") << std::endl;
    std::cout << "  Has digit: " << (hasDigit ? "Yes" : "No") << std::endl;
    std::cout << "  Has special char: " << (hasSpecial ? "Yes" : "No") << std::endl;
    
    bool meetsAllRequirements = isLongEnough && hasUppercase && hasLowercase && hasDigit && hasSpecial;
    std::cout << "Password is " << (meetsAllRequirements ? "strong" : "weak") << std::endl;
    
    // IP address filtering
    std::cout << "\n2. IP address filtering:\n";
    std::vector<std::string> accessLog = {
        "192.168.1.100 - GET /admin",
        "10.0.0.5 - POST /login",
        "172.16.0.1 - GET /index.html",
        "192.168.1.100 - POST /admin/config",
        "10.0.0.5 - GET /dashboard"
    };
    
    // Filter log entries from blocked IPs
    std::cout << "Suspicious access attempts from blocked IPs:" << std::endl;
    for (const auto& entry : accessLog) {
        // Extract IP address from log entry
        std::string ip = entry.substr(0, entry.find(' '));
        
        // Check if IP is in the blocked list
        if (blockedIPs.find(ip) != blockedIPs.end()) {
            std::cout << "  " << entry << std::endl;
        }
    }
    
    // Event correlation
    std::cout << "\n3. Event correlation:\n";
    std::multimap<std::string, std::string> securityAlerts;
    
    // Add some alerts
    securityAlerts.insert({"192.168.1.100", "Failed login attempt"});
    securityAlerts.insert({"192.168.1.100", "Password reset request"});
    securityAlerts.insert({"192.168.1.100", "Admin access attempt"});
    securityAlerts.insert({"10.0.0.5", "Failed login attempt"});
    securityAlerts.insert({"172.16.0.1", "File access attempt"});
    
    // Find all alerts for a specific IP
    std::string targetIP = "192.168.1.100";
    auto range = securityAlerts.equal_range(targetIP);
    
    std::cout << "All alerts for IP " << targetIP << ":" << std::endl;
    for (auto it = range.first; it != range.second; ++it) {
        std::cout << "  " << it->second << std::endl;
    }
    
    std::cout << "\n=== End of STL Demonstration ===\n";
    
    return 0;
}

