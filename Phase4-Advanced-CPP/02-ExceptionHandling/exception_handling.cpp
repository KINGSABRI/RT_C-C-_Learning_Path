/**
 * Exception Handling in C++ - Cybersecurity Perspective
 * 
 * This program demonstrates exception handling techniques in C++
 * with a focus on security applications.
 */

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <functional>

// Custom exception hierarchy for security-related exceptions
class SecurityException : public std::runtime_error {
public:
    explicit SecurityException(const std::string& message)
        : std::runtime_error(message) {}
};

class AuthenticationException : public SecurityException {
public:
    explicit AuthenticationException(const std::string& message)
        : SecurityException("Authentication error: " + message) {}
};

class AuthorizationException : public SecurityException {
public:
    explicit AuthorizationException(const std::string& message)
        : SecurityException("Authorization error: " + message) {}
};

class ValidationException : public SecurityException {
public:
    explicit ValidationException(const std::string& message)
        : SecurityException("Validation error: " + message) {}
};

class CryptographicException : public SecurityException {
public:
    explicit CryptographicException(const std::string& message)
        : SecurityException("Cryptographic error: " + message) {}
};

// RAII (Resource Acquisition Is Initialization) example
class SecureFile {
private:
    std::fstream file;
    std::string filename;
    bool is_open;
    
public:
    // Constructor acquires the resource
    explicit SecureFile(const std::string& filename) 
        : filename(filename), is_open(false) {
        try {
            file.open(filename, std::ios::in | std::ios::out);
            if (!file) {
                throw std::runtime_error("Failed to open file: " + filename);
            }
            is_open = true;
            std::cout << "File opened: " << filename << std::endl;
        } catch (const std::exception& e) {
            // Handle constructor failure
            std::cerr << "Error in SecureFile constructor: " << e.what() << std::endl;
            throw; // Re-throw to signal failure
        }
    }
    
    // Destructor releases the resource
    ~SecureFile() {
        try {
            if (is_open) {
                file.close();
                std::cout << "File closed: " << filename << std::endl;
            }
        } catch (...) {
            // Never throw from a destructor
            std::cerr << "Error closing file in destructor" << std::endl;
        }
    }
    
    // Read from the file
    std::string read(size_t length) {
        if (!is_open) {
            throw SecurityException("Attempting to read from a closed file");
        }
        
        std::string buffer(length, '\0');
        if (!file.read(&buffer[0], length)) {
            if (file.eof()) {
                buffer.resize(file.gcount());
            } else {
                throw std::runtime_error("Error reading from file");
            }
        }
        return buffer;
    }
    
    // Write to the file
    void write(const std::string& data) {
        if (!is_open) {
            throw SecurityException("Attempting to write to a closed file");
        }
        
        if (!file.write(data.c_str(), data.length())) {
            throw std::runtime_error("Error writing to file");
        }
        file.flush();
    }
    
    // Explicitly close the file
    void close() {
        if (is_open) {
            file.close();
            is_open = false;
            std::cout << "File explicitly closed: " << filename << std::endl;
        }
    }
    
    // Deleted copy constructor and assignment operator
    SecureFile(const SecureFile&) = delete;
    SecureFile& operator=(const SecureFile&) = delete;
    
    // Move constructor
    SecureFile(SecureFile&& other) noexcept
        : filename(std::move(other.filename)), is_open(other.is_open) {
        file.swap(other.file);
        other.is_open = false;
    }
    
    // Move assignment operator
    SecureFile& operator=(SecureFile&& other) noexcept {
        if (this != &other) {
            if (is_open) {
                file.close();
            }
            filename = std::move(other.filename);
            file.swap(other.file);
            is_open = other.is_open;
            other.is_open = false;
        }
        return *this;
    }
};

// Function to demonstrate basic exception handling
void demonstrateBasicExceptionHandling() {
    std::cout << "\n=== Basic Exception Handling ===\n";
    
    try {
        std::cout << "Attempting to allocate a large amount of memory...\n";
        
        // Try to allocate a very large amount of memory
        std::vector<int> huge_vector(std::numeric_limits<int>::max() / 10);
        
        std::cout << "Memory allocation succeeded (unlikely)\n";
    } catch (const std::bad_alloc& e) {
        std::cout << "Caught bad_alloc exception: " << e.what() << "\n";
        std::cout << "Handled memory allocation failure gracefully\n";
    }
    
    try {
        std::cout << "\nAttempting to access an out-of-bounds vector element...\n";
        
        std::vector<int> vec = {1, 2, 3};
        
        // Try to access an out-of-bounds element
        std::cout << "Element at index 5: " << vec.at(5) << "\n";
        
        std::cout << "Access succeeded (shouldn't happen)\n";
    } catch (const std::out_of_range& e) {
        std::cout << "Caught out_of_range exception: " << e.what() << "\n";
        std::cout << "Prevented potential memory access violation\n";
    }
}

// Function to demonstrate custom security exceptions
void demonstrateSecurityExceptions() {
    std::cout << "\n=== Custom Security Exceptions ===\n";
    
    // Simulated authentication function
    auto authenticate = [](const std::string& username, const std::string& password) {
        if (username.empty() || password.empty()) {
            throw ValidationException("Username and password cannot be empty");
        }
        
        if (username != "admin" || password != "secure_password") {
            throw AuthenticationException("Invalid username or password");
        }
        
        std::cout << "Authentication successful for user: " << username << "\n";
    };
    
    // Simulated authorization function
    auto checkAccess = [](const std::string& username, const std::string& resource) {
        if (username != "admin" && resource == "admin_panel") {
            throw AuthorizationException("User does not have access to the resource");
        }
        
        std::cout << "Authorization successful for user: " << username << " to access: " << resource << "\n";
    };
    
    // Test with valid credentials
    try {
        std::cout << "Attempting authentication with valid credentials...\n";
        authenticate("admin", "secure_password");
        checkAccess("admin", "admin_panel");
    } catch (const SecurityException& e) {
        std::cout << "Security exception: " << e.what() << "\n";
    }
    
    // Test with invalid credentials
    try {
        std::cout << "\nAttempting authentication with invalid credentials...\n";
        authenticate("admin", "wrong_password");
    } catch (const AuthenticationException& e) {
        std::cout << "Caught exception: " << e.what() << "\n";
    }
    
    // Test with empty credentials
    try {
        std::cout << "\nAttempting authentication with empty credentials...\n";
        authenticate("", "");
    } catch (const ValidationException& e) {
        std::cout << "Caught exception: " << e.what() << "\n";
    }
    
    // Test with unauthorized access
    try {
        std::cout << "\nAttempting unauthorized access...\n";
        authenticate("user", "user_password"); // This would throw in a real system
        checkAccess("user", "admin_panel");
    } catch (const AuthorizationException& e) {
        std::cout << "Caught exception: " << e.what() << "\n";
    } catch (const AuthenticationException& e) {
        // In a real system, we'd catch this from the authenticate call
        std::cout << "Caught exception: " << e.what() << "\n";
    }
}

// Function to demonstrate RAII pattern
void demonstrateRAII() {
    std::cout << "\n=== RAII Pattern ===\n";
    
    try {
        // Create a temporary file for demonstration
        {
            std::ofstream temp("temp_file.txt");
            temp << "This is a test file for RAII demonstration." << std::endl;
        }
        
        // Use RAII to manage file resource
        std::cout << "Creating SecureFile object...\n";
        SecureFile file("temp_file.txt");
        
        // Use the file
        std::cout << "Writing to file...\n";
        file.write("Sensitive data that should be properly handled");
        
        std::cout << "Reading from file...\n";
        file.write("More data");
        
        // File will be automatically closed when 'file' goes out of scope
        std::cout << "SecureFile object will go out of scope...\n";
    } catch (const std::exception& e) {
        std::cout << "Exception caught: " << e.what() << "\n";
    }
    
    // Clean up the temporary file
    std::remove("temp_file.txt");
}

// Function to demonstrate exception safety guarantees
void demonstrateExceptionSafety() {
    std::cout << "\n=== Exception Safety Guarantees ===\n";
    
    // Basic guarantee example - resource cleanup
    std::cout << "Basic guarantee example:\n";
    try {
        // Allocate resources
        int* array = new int[1000];
        std::cout << "Allocated memory\n";
        
        // Simulate an exception
        throw std::runtime_error("Simulated exception");
        
        // This code won't execute
        delete[] array;
        std::cout << "Deallocated memory (won't execute)\n";
    } catch (const std::exception& e) {
        std::cout << "Exception caught: " << e.what() << "\n";
        // Memory leak! The array wasn't deallocated
        std::cout << "Memory leak occurred - basic guarantee violated\n";
    }
    
    // Strong guarantee example - using RAII
    std::cout << "\nStrong guarantee example (using RAII):\n";
    try {
        // Use smart pointer for automatic cleanup
        auto array = std::make_unique<int[]>(1000);
        std::cout << "Allocated memory with smart pointer\n";
        
        // Simulate an exception
        throw std::runtime_error("Simulated exception");
        
        // This code won't execute
        std::cout << "This won't execute\n";
    } catch (const std::exception& e) {
        std::cout << "Exception caught: " << e.what() << "\n";
        std::cout << "No memory leak - smart pointer automatically cleaned up\n";
    }
    
    // Nothrow guarantee example
    std::cout << "\nNothrow guarantee example:\n";
    try {
        // Operations that won't throw
        int a = 5;
        int b = 10;
        int c = a + b;
        std::cout << "Result of addition: " << c << "\n";
        
        // This might throw, but it's outside the nothrow section
        if (c > 10) {
            throw std::runtime_error("Simulated exception");
        }
    } catch (const std::exception& e) {
        std::cout << "Exception caught: " << e.what() << "\n";
    }
}

// Function to demonstrate exception handling best practices
void demonstrateExceptionBestPractices() {
    std::cout << "\n=== Exception Handling Best Practices ===\n";
    
    // 1. Use specific exception types
    std::cout << "1. Use specific exception types:\n";
    try {
        throw AuthenticationException("Password expired");
    } catch (const AuthenticationException& e) {
        std::cout << "Caught specific exception: " << e.what() << "\n";
    } catch (const SecurityException& e) {
        std::cout << "Caught base security exception\n";
    } catch (const std::exception& e) {
        std::cout << "Caught standard exception\n";
    } catch (...) {
        std::cout << "Caught unknown exception\n";
    }
    
    // 2. Exception translation
    std::cout << "\n2. Exception translation:\n";
    try {
        try {
            // Low-level exception
            throw std::runtime_error("Database connection failed");
        } catch (const std::runtime_error& e) {
            // Translate to a more meaningful high-level exception
            throw AuthenticationException(std::string("Cannot verify user: ") + e.what());
        }
    } catch (const AuthenticationException& e) {
        std::cout << "Caught translated exception: " << e.what() << "\n";
    }
    
    // 3. Function try blocks
    std::cout << "\n3. Function try blocks:\n";
    
    class Resource {
    public:
        Resource(int id) try : id_(id) {
            if (id < 0) {
                throw std::invalid_argument("ID cannot be negative");
            }
            std::cout << "Resource created with ID: " << id << "\n";
        } catch (const std::exception& e) {
            std::cout << "Exception in constructor: " << e.what() << "\n";
            throw; // Re-throw to signal construction failure
        }
        
    private:
        int id_;
    };
    
    try {
        Resource r1(42);  // Valid
        Resource r2(-1);  // Invalid
    } catch (const std::exception& e) {
        std::cout << "Resource creation failed: " << e.what() << "\n";
    }
}

// Function to demonstrate security implications of exceptions
void demonstrateSecurityImplications() {
    std::cout << "\n=== Security Implications of Exceptions ===\n";
    
    // 1. Information leakage
    std::cout << "1. Information leakage:\n";
    try {
        // Simulate a database query
        throw std::runtime_error("MySQL error: Table 'users' doesn't exist in database 'app_db'");
    } catch (const std::exception& e) {
        // BAD: Exposing internal details to the user
        // std::cout << "Error: " << e.what() << "\n";
        
        // GOOD: Log the detailed error internally, but show a generic message to the user
        std::cerr << "Internal error details (for logs): " << e.what() << "\n";
        std::cout << "User-facing error message: An internal error occurred. Please contact support.\n";
    }
    
    // 2. Exception safety in security-critical code
    std::cout << "\n2. Exception safety in security-critical code:\n";
    
    // Simulate a sensitive operation
    auto sensitiveOperation = []() {
        std::vector<int> sensitive_data = {1, 2, 3, 4, 5};
        
        try {
            // Perform operation that might throw
            throw std::runtime_error("Operation failed");
            
            // This won't std::runtime_error("Operation failed");
            
            // This won't execute
            std::cout << "Operation completed successfully\n";
        } catch (const std::exception& e) {
            // Secure cleanup of sensitive data
            for (auto& value : sensitive_data) {
                value = 0;  // Zero out sensitive data
            }
            
            std::cout << "Exception caught, sensitive data securely wiped\n";
            throw; // Re-throw the exception
        }
    };
    
    try {
        sensitiveOperation();
    } catch (const std::exception& e) {
        std::cout << "Caught re-thrown exception: " << e.what() << "\n";
    }
    
    // 3. Denial of service through exception handling
    std::cout << "\n3. Preventing denial of service through exceptions:\n";
    
    int request_count = 0;
    const int max_requests = 3;
    
    for (int i = 0; i < 5; i++) {
        try {
            // Check for too many requests
            if (++request_count > max_requests) {
                throw SecurityException("Too many requests");
            }
            
            std::cout << "Processing request " << request_count << "\n";
        } catch (const SecurityException& e) {
            std::cout << "Request denied: " << e.what() << "\n";
        }
    }
}

int main() {
    std::cout << "=== Exception Handling in C++: Cybersecurity Perspective ===\n";
    
    // Demonstrate basic exception handling
    demonstrateBasicExceptionHandling();
    
    // Demonstrate custom security exceptions
    demonstrateSecurityExceptions();
    
    // Demonstrate RAII pattern
    demonstrateRAII();
    
    // Demonstrate exception safety guarantees
    demonstrateExceptionSafety();
    
    // Demonstrate exception handling best practices
    demonstrateExceptionBestPractices();
    
    // Demonstrate security implications of exceptions
    demonstrateSecurityImplications();
    
    std::cout << "\n=== Security Best Practices for Exception Handling ===\n";
    std::cout << "1. Use RAII to ensure resource cleanup even when exceptions occur\n";
    std::cout << "2. Create a hierarchy of security-specific exception classes\n";
    std::cout << "3. Catch specific exceptions before general ones\n";
    std::cout << "4. Avoid exposing sensitive information in exception messages\n";
    std::cout << "5. Always clean up sensitive data before propagating exceptions\n";
    std::cout << "6. Use exception specifications and noexcept where appropriate\n";
    std::cout << "7. Consider exception safety guarantees in security-critical code\n";
    
    return 0;
}

