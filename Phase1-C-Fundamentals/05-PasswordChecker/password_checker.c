/**
 * Password Strength Checker
 * 
 * This program demonstrates control flow concepts by implementing
 * a password strength checker with various security rules.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

// Function to check if a password meets the minimum length requirement
bool checkLength(const char* password, int minLength) {
    return strlen(password) >= minLength;
}

// Function to check if a password contains uppercase letters
bool containsUppercase(const char* password) {
    while (*password) {
        if (isupper(*password)) {
            return true;
        }
        password++;
    }
    return false;
}

// Function to check if a password contains lowercase letters
bool containsLowercase(const char* password) {
    while (*password) {
        if (islower(*password)) {
            return true;
        }
        password++;
    }
    return false;
}

// Function to check if a password contains digits
bool containsDigit(const char* password) {
    while (*password) {
        if (isdigit(*password)) {
            return true;
        }
        password++;
    }
    return false;
}

// Function to check if a password contains special characters
bool containsSpecialChar(const char* password) {
    const char* specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    
    while (*password) {
        const char* special = specialChars;
        while (*special) {
            if (*password == *special) {
                return true;
            }
            special++;
        }
        password++;
    }
    return false;
}

// Function to check if a password contains sequential characters
bool containsSequential(const char* password) {
    for (int i = 0; password[i] && password[i+1] && password[i+2]; i++) {
        // Check for alphabetical sequences (abc, def, etc.)
        if (isalpha(password[i]) && isalpha(password[i+1]) && isalpha(password[i+2])) {
            if (tolower(password[i+1]) == tolower(password[i]) + 1 &&
                tolower(password[i+2]) == tolower(password[i]) + 2) {
                return true;
            }
        }
        
        // Check for numerical sequences (123, 456, etc.)
        if (isdigit(password[i]) && isdigit(password[i+1]) && isdigit(password[i+2])) {
            if (password[i+1] == password[i] + 1 && password[i+2] == password[i] + 2) {
                return true;
            }
        }
    }
    return false;
}

// Function to check for repeated characters
bool containsRepeated(const char* password) {
    for (int i = 0; password[i] && password[i+1] && password[i+2]; i++) {
        if (password[i] == password[i+1] && password[i] == password[i+2]) {
            return true;
        }
    }
    return false;
}

// Function to check if a password is in a common password list
bool isCommonPassword(const char* password) {
    // This is a simplified list; in a real application, you'd use a more comprehensive list
    const char* commonPasswords[] = {
        "password", "123456", "qwerty", "admin", "welcome",
        "password123", "abc123", "letmein", "monkey", "123456789"
    };
    
    int count = sizeof(commonPasswords) / sizeof(commonPasswords[0]);
    
    for (int i = 0; i < count; i++) {
        if (strcmp(password, commonPasswords[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

// Function to calculate password strength score (0-100)
int calculatePasswordStrength(const char* password) {
    int score = 0;
    
    // Length check (up to 30 points)
    int length = strlen(password);
    if (length >= 12) {
        score += 30;
    } else if (length >= 8) {
        score += 20;
    } else if (length >= 6) {
        score += 10;
    }
    
    // Character variety (up to 40 points)
    if (containsUppercase(password)) score += 10;
    if (containsLowercase(password)) score += 10;
    if (containsDigit(password)) score += 10;
    if (containsSpecialChar(password)) score += 10;
    
    // Penalize for sequential characters (e.g., abc, 123)
    if (containsSequential(password)) score -= 15;
    
    // Penalize for repeated characters (e.g., aaa, 111)
    if (containsRepeated(password)) score -= 15;
    
    // Penalize common passwords
    if (isCommonPassword(password)) score -= 30;
    
    // Ensure score is within 0-100 range
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    
    return score;
}

// Function to get strength description based on score
const char* getStrengthDescription(int score) {
    if (score >= 80) return "Very Strong";
    if (score >= 60) return "Strong";
    if (score >= 40) return "Moderate";
    if (score >= 20) return "Weak";
    return "Very Weak";
}

// Function to provide password improvement suggestions
void suggestImprovements(const char* password) {
    printf("Suggestions for improvement:\n");
    
    // Check length
    if (!checkLength(password, 12)) {
        printf("- Make your password longer (at least 12 characters)\n");
    }
    
    // Check character variety
    if (!containsUppercase(password)) {
        printf("- Add uppercase letters (A-Z)\n");
    }
    
    if (!containsLowercase(password)) {
        printf("- Add lowercase letters (a-z)\n");
    }
    
    if (!containsDigit(password)) {
        printf("- Add numbers (0-9)\n");
    }
    
    if (!containsSpecialChar(password)) {
        printf("- Add special characters (e.g., !@#$%%^&*)\n");
    }
    
    // Check for sequential characters
    if (containsSequential(password)) {
        printf("- Avoid sequential characters (e.g., abc, 123)\n");
    }
    
    // Check for repeated characters
    if (containsRepeated(password)) {
        printf("- Avoid repeated characters (e.g., aaa, 111)\n");
    }
    
    // Check if it's a common password
    if (isCommonPassword(password)) {
        printf("- Avoid commonly used passwords\n");
    }
    
    printf("- Consider using a passphrase (multiple words with spaces)\n");
}

int main() {
    printf("=== Password Strength Checker ===\n\n");
    
    // Test passwords
    const char* passwords[] = {
        "password",           // Very weak (common password)
        "123456",             // Very weak (common password, all digits)
        "securityC",          // Weak (no digits or special chars)
        "Security2023",       // Moderate (no special chars)
        "S3cur1ty!",          // Strong (good variety but a bit short)
        "Th1s!Is@A#Strong$Pwd" // Very strong (long with good variety)
    };
    
    int numPasswords = sizeof(passwords) / sizeof(passwords[0]);
    
    for (int i = 0; i < numPasswords; i++) {
        const char* password = passwords[i];
        int score = calculatePasswordStrength(password);
        const char* strength = getStrengthDescription(score);
        
        printf("Password: %s\n", password);
        printf("Length: %lu characters\n", strlen(password));
        printf("Strength: %d/100 (%s)\n", score, strength);
        
        // Detailed analysis
        printf("Analysis:\n");
        printf("- Contains uppercase letters: %s\n", containsUppercase(password) ? "Yes" : "No");
        printf("- Contains lowercase letters: %s\n", containsLowercase(password) ? "Yes" : "No");
        printf("- Contains digits: %s\n", containsDigit(password) ? "Yes" : "No");
        printf("- Contains special characters: %s\n", containsSpecialChar(password) ? "Yes" : "No");
        printf("- Contains sequential characters: %s\n", containsSequential(password) ? "Yes" : "No");
        printf("- Contains repeated characters: %s\n", containsRepeated(password) ? "Yes" : "No");
        printf("- Is a common password: %s\n", isCommonPassword(password) ? "Yes" : "No");
        
        // If password is not very strong, suggest improvements
        if (score < 80) {
            suggestImprovements(password);
        }
        
        printf("\n-----------------------------------\n\n");
    }
    
    printf("=== Security Best Practices for Passwords ===\n");
    printf("1. Use a unique password for each account\n");
    printf("2. Make passwords at least 12 characters long\n");
    printf("3. Include a mix of character types\n");
    printf("4. Avoid personal information\n");
    printf("5. Change passwords periodically\n");
    printf("6. Consider using a password manager\n");
    
    return 0;
}

