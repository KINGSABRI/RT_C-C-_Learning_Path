/**
 * Templates and Metaprogramming in C++ - Cybersecurity Perspective
 * 
 * This program demonstrates templates and metaprogramming techniques in C++
 * with a focus on security applications.
 */

#include <iostream>
#include <string>
#include <vector>
#include <type_traits>
#include <memory>
#include <array>

// Forward declarations
template<typename T> class SecureContainer;
template<typename T> class TypeTraits;

/**
 * Basic function template example - secure comparison
 * 
 * This function template provides a timing-attack resistant comparison
 * for sensitive data like password hashes or tokens
 */
template<typename T>
bool secureCompare(const T& a, const T& b) {
    // Get sizes for the comparison
    size_t size_a = sizeof(a);
    size_t size_b = sizeof(b);
    
    // If sizes differ, they're not equal, but still do the comparison
    // to avoid timing attacks
    bool equal = (size_a == size_b);
    
    // Convert to byte arrays for comparison
    const unsigned char* bytes_a = reinterpret_cast<const unsigned char*>(&a);
    const unsigned char* bytes_b = reinterpret_cast<const unsigned char*>(&b);
    
    // Compare all bytes with constant-time algorithm
    // This prevents timing attacks by ensuring the comparison
    // takes the same amount of time regardless of where differences occur
    for (size_t i = 0; i < (size_a < size_b ? size_a : size_b); i++) {
        equal &= (bytes_a[i] == bytes_b[i]);
        // Note: We don't short-circuit with a break to maintain constant time
    }
    
    return equal;
}

// Specialization for std::string
template<>
bool secureCompare<std::string>(const std::string& a, const std::string& b) {
    // Get sizes for the comparison
    size_t size_a = a.size();
    size_t size_b = b.size();
    
    // If sizes differ, they're not equal, but still do the comparison
    bool equal = (size_a == size_b);
    
    // Compare all characters with constant-time algorithm
    for (size_t i = 0; i < (size_a < size_b ? size_a : size_b); i++) {
        equal &= (a[i] == b[i]);
        // Note: We don't short-circuit with a break to maintain constant time
    }
    
    return equal;
}

/**
 * Class template for secure data storage
 * 
 * This template provides a secure container for sensitive data
 * with automatic memory wiping on destruction
 */
template<typename T>
class SecureContainer {
private:
    T data;
    bool valid;
    
    // Helper to securely wipe memory
    void wipeMemory() {
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(&data);
        for (size_t i = 0; i < sizeof(T); i++) {
            p[i] = 0;
        }
    }
    
public:
    // Constructor
    SecureContainer() : valid(false) {
        // Initialize memory to zero
        wipeMemory();
    }
    
    // Constructor with initial data
    explicit SecureContainer(const T& initialData) : data(initialData), valid(true) {}
    
    // Destructor - automatically wipes memory
    ~SecureContainer() {
        wipeMemory();
        valid = false;
    }
    
    // Copy constructor - disabled for security
    SecureContainer(const SecureContainer&) = delete;
    
    // Copy assignment - disabled for security
    SecureContainer& operator=(const SecureContainer&) = delete;
    
    // Move constructor
    SecureContainer(SecureContainer&& other) noexcept : valid(other.valid) {
        data = std::move(other.data);
        other.valid = false;
        other.wipeMemory();
    }
    
    // Move assignment
    SecureContainer& operator=(SecureContainer&& other) noexcept {
        if (this != &other) {
            wipeMemory();
            data = std::move(other.data);
            valid = other.valid;
            other.valid = false;
            other.wipeMemory();
        }
        return *this;
    }
    
    // Set data
    void setData(const T& newData) {
        data = newData;
        valid = true;
    }
    
    // Get data (const reference)
    const T& getData() const {
        if (!valid) {
            throw std::runtime_error("Attempting to access invalid secure data");
        }
        return data;
    }
    
    // Check if data is valid
    bool isValid() const {
        return valid;
    }
    
    // Explicitly invalidate and wipe data
    void clear() {
        wipeMemory();
        valid = false;
    }
};

/**
 * Type traits for security-related properties
 */
template<typename T>
class TypeTraits {
public:
    // Check if type is secure for storing sensitive data
    static constexpr bool isSecureStorage() {
        // By default, assume types are not secure for sensitive data
        return false;
    }
    
    // Check if type has secure comparison
    static constexpr bool hasSecureComparison() {
        // By default, assume types don't have secure comparison
        return false;
    }
    
    // Check if type is memory-safe (no buffer overflows)
    static constexpr bool isMemorySafe() {
        // By default, assume raw types are not memory-safe
        return false;
    }
};

// Specialization for SecureContainer
template<typename T>
class TypeTraits<SecureContainer<T>> {
public:
    static constexpr bool isSecureStorage() {
        return true;
    }
    
    static constexpr bool hasSecureComparison() {
        return true;
    }
    
    static constexpr bool isMemorySafe() {
        return true;
    }
};

// Specialization for std::string
template<>
class TypeTraits<std::string> {
public:
    static constexpr bool isSecureStorage() {
        return false; // std::string doesn't wipe memory on destruction
    }
    
    static constexpr bool hasSecureComparison() {
        return false; // std::string uses short-circuit comparison
    }
    
    static constexpr bool isMemorySafe() {
        return true; // std::string handles memory safely
    }
};

// Specialization for std::vector
template<typename T>
class TypeTraits<std::vector<T>> {
public:
    static constexpr bool isSecureStorage() {
        return TypeTraits<T>::isSecureStorage();
    }
    
    static constexpr bool hasSecureComparison() {
        return false;
    }
    
    static constexpr bool isMemorySafe() {
        return true; // std::vector handles memory safely
    }
};

/**
 * Variadic template example - secure hash combiner
 */
template<typename T>
size_t hashCombine(const T& value) {
    return std::hash<T>{}(value);
}

template<typename T, typename... Args>
size_t hashCombine(const T& first, const Args&... args) {
    size_t seed = hashCombine(args...);
    return std::hash<T>{}(first) ^ (seed << 1);
}

/**
 * Compile-time security checks using template metaprogramming
 */
template<typename T>
constexpr bool isSecureType() {
    return TypeTraits<T>::isSecureStorage() && 
           TypeTraits<T>::hasSecureComparison() && 
           TypeTraits<T>::isMemorySafe();
}

// Compile-time assertion helper
template<bool Condition, typename T = void>
struct SecurityAssert;

// Specialization for true condition
template<typename T>
struct SecurityAssert<true, T> {
    using type = T;
};

// Usage: SecurityAssert<isSecureType<T>()>::type

/**
 * Template for a secure configuration manager
 */
template<typename KeyType, typename ValueType>
class SecureConfigManager {
private:
    struct ConfigEntry {
        KeyType key;
        ValueType value;
        bool sensitive;
    };
    
    std::vector<ConfigEntry> entries;
    
public:
    // Add a configuration entry
    void addConfig(const KeyType& key, const ValueType& value, bool sensitive = false) {
        // For sensitive data, ensure we're using a secure type
        if (sensitive && !TypeTraits<ValueType>::isSecureStorage()) {
            std::cerr << "Warning: Storing sensitive data in a non-secure type" << std::endl;
        }
        
        entries.push_back({key, value, sensitive});
    }
    
    // Get a configuration value
    ValueType getConfig(const KeyType& key) const {
        for (const auto& entry : entries) {
            if (entry.key == key) {
                return entry.value;
            }
        }
        throw std::runtime_error("Configuration key not found");
    }
    
    // Check if a configuration is sensitive
    bool isSensitive(const KeyType& key) const {
        for (const auto& entry : entries) {
            if (entry.key == key) {
                return entry.sensitive;
            }
        }
        return false;
    }
    
    // Print all non-sensitive configurations
    void printNonSensitiveConfigs() const {
        std::cout << "Non-sensitive configurations:" << std::endl;
        for (const auto& entry : entries) {
            if (!entry.sensitive) {
                std::cout << "  " << entry.key << ": " << entry.value << std::endl;
            }
        }
    }
};

/**
 * Compile-time buffer size checking
 */
template<size_t BufferSize, size_t DataSize>
struct BufferSizeCheck {
    static_assert(BufferSize >= DataSize, "Buffer size is too small for data");
    
    static constexpr bool isSafe() {
        return BufferSize >= DataSize;
    }
};

/**
 * Demonstration of template metaprogramming for security
 */
void demonstrateTemplateMetaprogramming() {
    std::cout << "\n=== Template Metaprogramming for Security ===\n";
    
    // Compile-time buffer size checking
    constexpr size_t bufferSize = 16;
    constexpr size_t dataSize1 = 10;
    constexpr size_t dataSize2 = 20;
    
    std::cout << "Buffer size: " << bufferSize << " bytes\n";
    std::cout << "Data size 1: " << dataSize1 << " bytes\n";
    std::cout << "Data size 2: " << dataSize2 << " bytes\n";
    
    std::cout << "Is buffer safe for data 1? " 
              << (BufferSizeCheck<bufferSize, dataSize1>::isSafe() ? "Yes" : "No") << "\n";
    
    // This would cause a compile-time error:
    // BufferSizeCheck<bufferSize, dataSize2>::isSafe();
    
    std::cout << "Compile-time checks prevent buffer overflows by failing compilation\n";
    std::cout << "when buffer sizes are too small for the data.\n";
}

int main() {
    std::cout << "=== Templates and Metaprogramming in C++: Cybersecurity Perspective ===\n";
    
    // Demonstrate secure comparison
    std::cout << "\n=== Secure Comparison ===\n";
    
    std::string password1 = "SecurePassword123!";
    std::string password2 = "SecurePassword123!";
    std::string password3 = "DifferentPassword!";
    
    std::cout << "Comparing passwords with timing-attack resistant function:\n";
    std::cout << "password1 == password2: " << (secureCompare(password1, password2) ? "true" : "false") << "\n";
    std::cout << "password1 == password3: " << (secureCompare(password1, password3) ? "true" : "false") << "\n";
    
    // Demonstrate secure container
    std::cout << "\n=== Secure Container ===\n";
    
    // Create a secure container for a password
    SecureContainer<std::string> securePassword(password1);
    std::cout << "Stored password: " << securePassword.getData() << "\n";
    
    // Clear the secure container
    std::cout << "Clearing secure container...\n";
    securePassword.clear();
    
    // This would throw an exception:
    try {
        std::cout << "Attempting to access cleared data...\n";
        std::cout << "Password: " << securePassword.getData() << "\n";
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
    }
    
    // Demonstrate type traits
    std::cout << "\n=== Type Traits for Security ===\n";
    
    std::cout << "std::string is secure storage: " 
              << (TypeTraits<std::string>::isSecureStorage() ? "Yes" : "No") << "\n";
    
    std::cout << "SecureContainer<std::string> is secure storage: " 
              << (TypeTraits<SecureContainer<std::string>>::isSecureStorage() ? "Yes" : "No") << "\n";
    
    std::cout << "std::string is memory-safe: " 
              << (TypeTraits<std::string>::isMemorySafe() ? "Yes" : "No") << "\n";
    
    // Demonstrate secure config manager
    std::cout << "\n=== Secure Configuration Manager ===\n";
    
    SecureConfigManager<std::string, std::string> configManager;
    
    // Add some configurations
    configManager.addConfig("server_address", "192.168.1.100", false);
    configManager.addConfig("server_port", "8080", false);
    configManager.addConfig("api_key", "sk_live_1234567890abcdef", true);
    configManager.addConfig("debug_mode", "true", false);
    
    // Print non-sensitive configurations
    configManager.printNonSensitiveConfigs();
    
    // Demonstrate hash combine
    std::cout << "\n=== Hash Combine ===\n";
    
    std::string username = "admin";
    std::string domain = "example.com";
    int timestamp = 1623456789;
    
    size_t combinedHash = hashCombine(username, domain, timestamp);
    std::cout << "Combined hash of multiple values: " << combinedHash << "\n";
    
    // Demonstrate template metaprogramming
    demonstrateTemplateMetaprogramming();
    
    std::cout << "\n=== Security Benefits of Templates and Metaprogramming ===\n";
    std::cout << "1. Compile-time security checks prevent runtime vulnerabilities\n";
    std::cout << "2. Type-safe containers reduce memory corruption risks\n";
    std::cout << "3. Secure comparison functions prevent timing attacks\n";
    std::cout << "4. Automatic memory wiping protects sensitive data\n";
    std::cout << "5. Generic code reduces duplication and potential for errors\n";
    
    return 0;
}

