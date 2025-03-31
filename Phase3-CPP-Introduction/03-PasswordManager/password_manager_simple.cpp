#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>

/**
 * Simple Secure Password Manager
 * 
 * This is a simplified version of the password manager that demonstrates
 * the core concepts without the full implementation complexity.
 */

// Class to check password strength
class PasswordStrengthChecker {
public:
    // Check password strength and return a score (0-100)
    static int checkStrength(const std::string& password) {
        int score = 0;
        
        // Check length
        if (password.length() >= 8) score += 10;
        if (password.length() >= 12) score += 10;
        if (password.length() >= 16) score += 10;
        
        // Check for uppercase letters
        if (std::any_of(password.begin(), password.end(), ::isupper)) {
            score += 10;
        }
        
        // Check for lowercase letters
        if (std::any_of(password.begin(), password.end(), ::islower)) {
            score += 10;
        }
        
        // Check for digits
        if (std::any_of(password.begin(), password.end(), ::isdigit)) {
            score += 10;
        }
        
        // Check for special characters
        if (std::any_of(password.begin(), password.end(), 
                        [](char c) { return !::isalnum(c); })) {
            score += 10;
        }
        
        // Check for mixed character types
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        
        for (char c : password) {
            if (::isupper(c)) hasUpper = true;
            else if (::islower(c)) hasLower = true;
            else if (::isdigit(c)) hasDigit = true;
            else hasSpecial = true;
        }
        
        int typesCount = hasUpper + hasLower + hasDigit + hasSpecial;
        score += (typesCount - 1) * 10;  // -1 because we already counted each type above
        
        // Ensure score is between 0 and 100
        if (score < 0) score = 0;
        if (score > 100) score = 100;
        
        return score;
    }
    
    // Get a description of the password strength
    static std::string getStrengthDescription(int score) {
        if (score >= 80) return "Very Strong";
        if (score >= 60) return "Strong";
        if (score >= 40) return "Moderate";
        if (score >= 20) return "Weak";
        return "Very Weak";
    }
    
    // Get suggestions to improve password strength
    static std::vector<std::string> getImprovement(const std::string& password) {
        std::vector<std::string> suggestions;
        
        // Check length
        if (password.length() < 12) {
            suggestions.push_back("Make your password longer (at least 12 characters)");
        }
        
        // Check for uppercase letters
        if (!std::any_of(password.begin(), password.end(), ::isupper)) {
            suggestions.push_back("Add uppercase letters");
        }
        
        // Check for lowercase letters
        if (!std::any_of(password.begin(), password.end(), ::islower)) {
            suggestions.push_back("Add lowercase letters");
        }
        
        // Check for digits
        if (!std::any_of(password.begin(), password.end(), ::isdigit)) {
            suggestions.push_back("Add numbers");
        }
        
        // Check for special characters
        if (!std::any_of(password.begin(), password.end(), 
                         [](char c) { return !::isalnum(c); })) {
            suggestions.push_back("Add special characters (e.g., !@#$%^&*)");
        }
        
        return suggestions;
    }
};

// Class to generate secure passwords
class PasswordGenerator {
private:
    // Random number generator
    std::mt19937 rng;
    
public:
    // Constructor
    PasswordGenerator() {
        // Seed the random number generator
        rng.seed(std::chrono::system_clock::now().time_since_epoch().count());
    }
    
    // Generate a random password
    std::string generatePassword(int length = 16, 
                               bool includeUpper = true,
                               bool includeLower = true,
                               bool includeDigits = true,
                               bool includeSpecial = true) {
        // Define character sets
        const std::string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const std::string lowerChars = "abcdefghijklmnopqrstuvwxyz";
        const std::string digitChars = "0123456789";
        const std::string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
        
        // Combine selected character sets
        std::string allChars;
        if (includeUpper) allChars += upperChars;
        if (includeLower) allChars += lowerChars;
        if (includeDigits) allChars += digitChars;
        if (includeSpecial) allChars += specialChars;
        
        // If no character sets were selected, use all
        if (allChars.empty()) {
            allChars = upperChars + lowerChars + digitChars + specialChars;
        }
        
        // Distribution for selecting random characters
        std::uniform_int_distribution<size_t> dist(0, allChars.size() - 1);
        
        // Generate the password
        std::string password;
        password.reserve(length);
        
        for (int i = 0; i < length; ++i) {
            password += allChars[dist(rng)];
        }
        
        return password;
    }
};

// Class for a password entry
class PasswordEntry {
private:
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    
public:
    // Constructor
    PasswordEntry(const std::string& title, 
                 const std::string& username, 
                 const std::string& password,
                 const std::string& url = "",
                 const std::string& notes = "")
        : title(title),
          username(username),
          password(password),
          url(url),
          notes(notes) {
    }
    
    // Getters
    std::string getTitle() const { return title; }
    std::string getUsername() const { return username; }
    std::string getPassword() const { return password; }
    std::string getUrl() const { return url; }
    std::string getNotes() const { return notes; }
    
    // Setters
    void setPassword(const std::string& newPassword) { password = newPassword; }
    void setUsername(const std::string& newUsername) { username = newUsername; }
    void setUrl(const std::string& newUrl) { url = newUrl; }
    void setNotes(const std::string& newNotes) { notes = newNotes; }
};

// Main password manager class
class PasswordManager {
private:
    std::map<std::string, PasswordEntry> entries;
    PasswordGenerator generator;
    std::string masterPassword;
    bool isUnlocked;
    
public:
    // Constructor
    PasswordManager() : isUnlocked(false) {
        std::cout << "Password Manager initialized" << std::endl;
    }
    
    // Set the master password
    void setMasterPassword(const std::string& password) {
        masterPassword = password;
        
        // Check password strength
        int strength = PasswordStrengthChecker::checkStrength(password);
        std::cout << "Master password strength: " 
                  << strength << "/100 (" 
                  << PasswordStrengthChecker::getStrengthDescription(strength) 
                  << ")" << std::endl;
        
        if (strength < 60) {
            std::cout << "Warning: Your master password is not very strong." << std::endl;
            std::cout << "Suggestions for improvement:" << std::endl;
            
            auto suggestions = PasswordStrengthChecker::getImprovement(password);
            for (const auto& suggestion : suggestions) {
                std::cout << "- " << suggestion << std::endl;
            }
        }
        
        isUnlocked = true;
    }
    
    // Unlock the password manager
    bool unlock(const std::string& password) {
        if (password == masterPassword) {
            isUnlocked = true;
            std::cout << "Password manager unlocked" << std::endl;
            return true;
        } else {
            std::cout << "Incorrect master password" << std::endl;
            return false;
        }
    }
    
    // Lock the password manager
    void lock() {
        isUnlocked = false;
        std::cout << "Password manager locked" << std::endl;
    }
    
    // Add a password entry
    void addEntry(const std::string& title, 
                 const std::string& username, 
                 const std::string& password,
                 const std::string& url = "",
                 const std::string& notes = "") {
        if (!isUnlocked) {
            std::cout << "Password manager is locked" << std::endl;
            return;
        }
        
        // Check if entry already exists
        if (entries.find(title) != entries.end()) {
            std::cout << "Entry '" << title << "' already exists" << std::endl;
            return;
        }
        
        // Check password strength
        int strength = PasswordStrengthChecker::checkStrength(password);
        std::cout << "Password strength: " 
                  << strength << "/100 (" 
                  << PasswordStrengthChecker::getStrengthDescription(strength) 
                  << ")" << std::endl;
        
        // Create the entry
        entries.emplace(title, PasswordEntry(title, username, password, url, notes));
        std::cout << "Entry '" << title << "' added" << std::endl;
    }
    
    // Get a password entry
    PasswordEntry* getEntry(const std::string& title) {
        if (!isUnlocked) {
            std::cout << "Password manager is locked" << std::endl;
            return nullptr;
        }
        
        auto it = entries.find(title);
        if (it != entries.end()) {
            return &(it->second);
        } else {
            std::cout << "Entry '" << title << "' not found" << std::endl;
            return nullptr;
        }
    }
    
    // Remove a password entry
    bool removeEntry(const std::string& title) {
        if (!isUnlocked) {
            std::cout << "Password manager is locked" << std::endl;
            return false;
        }
        
        auto it = entries.find(title);
        if (it != entries.end()) {
            entries.erase(it);
            std::cout << "Entry '" << title << "' removed" << std::endl;
            return true;
        } else {
            std::cout << "Entry '" << title << "' not found" << std::endl;
            return false;
        }
    }
    
    // Generate a random password
    std::string generatePassword(int length = 16) {
        return generator.generatePassword(length);
    }
    
    // Print all entries
    void printAllEntries() {
        if (!isUnlocked) {
            std::cout << "Password manager is locked" << std::endl;
            return;
        }
        
        if (entries.empty()) {
            std::cout << "No entries found" << std::endl;
            return;
        }
        
        std::cout << "\n=== Password Entries ===\n";
        for (const auto& pair : entries) {
            const auto& entry = pair.second;
            std::cout << "Title: " << entry.getTitle() << std::endl;
            std::cout << "  Username: " << entry.getUsername() << std::endl;
            std::cout << "  URL: " << (entry.getUrl().empty() ? "(none)" : entry.getUrl()) << std::endl;
            std::cout << std::endl;
        }
    }
    
    // Print details of a specific entry
    void printEntryDetails(const std::string& title) {
        if (!isUnlocked) {
            std::cout << "Password manager is locked" << std::endl;
            return;
        }
        
        auto entry = getEntry(title);
        if (entry) {
            std::cout << "\n=== Entry Details ===\n";
            std::cout << "Title: " << entry->getTitle() << std::endl;
            std::cout << "Username: " << entry->getUsername() << std::endl;
            std::cout << "Password: " << entry->getPassword() << std::endl;
            
            if (!entry->getUrl().empty()) {
                std::cout << "URL: " << entry->getUrl() << std::endl;
            }
            
            if (!entry->getNotes().empty()) {
                std::cout << "Notes: " << entry->getNotes() << std::endl;
            }
            
            // Check password strength
            int strength = PasswordStrengthChecker::checkStrength(entry->getPassword());
            std::cout << "Password strength: " 
                      << strength << "/100 (" 
                      << PasswordStrengthChecker::getStrengthDescription(strength) 
                      << ")" << std::endl;
        }
    }
};

int main() {
    std::cout << "=== Simple Secure Password Manager ===\n\n";
    
    // Create a password manager
    PasswordManager manager;
    
    // Set the master password
    std::cout << "Please set a master password: ";
    std::string masterPassword;
    std::cin >> masterPassword;
    manager.setMasterPassword(masterPassword);
    
    // Add some password entries
    manager.addEntry("Google", "user@example.com", "Password123", "https://google.com");
    manager.addEntry("Facebook", "user@example.com", "Fb@123456", "https://facebook.com");
    manager.addEntry("Bank", "user123", "BankPass!@#");
    
    // Print all entries
    manager.printAllEntries();
    
    // Print details of a specific entry
    manager.printEntryDetails("Google");
    
    // Generate a random password
    std::cout << "\n=== Password Generation ===\n";
    std::cout << "Generated password: " << manager.generatePassword() << std::endl;
    
    // Lock the password manager
    manager.lock();
    
    // Try to access while locked
    manager.printAllEntries();  // Should show "Password manager is locked"
    
    // Unlock the password manager
    std::cout << "\nPlease enter the master password to unlock: ";
    std::cin >> masterPassword;
    manager.unlock(masterPassword);
    
    // Access after unlocking
    manager.printAllEntries();
    
    std::cout << "\n=== End of Demonstration ===\n";
    
    return 0;
}

