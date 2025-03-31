/**
 * Thread Safety in C++ - Cybersecurity Perspective
 * 
 * This program demonstrates thread safety techniques in C++
 * with a focus on security implications.
 */

#include <iostream>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <functional>
#include <condition_variable>
#include <future>

// Global mutex for demonstration
std::mutex global_mutex;

// Shared mutex for reader-writer scenarios
std::shared_mutex shared_mutex;

// Atomic counter for thread-safe operations
std::atomic<int> access_count{0};

// Condition variable for signaling between threads
std::condition_variable condition;
std::mutex condition_mutex;
bool data_ready = false;

/**
 * Basic thread safety demonstration with mutex
 */
void demonstrateBasicThreadSafety() {
    std::cout << "\n=== Basic Thread Safety with Mutex ===\n";
    
    // Shared resource (not thread-safe without protection)
    int shared_counter = 0;
    
    // Function that increments the counter without protection
    auto unsafe_increment = [&shared_counter]() {
        for (int i = 0; i < 1000; ++i) {
            // This is not thread-safe - race condition can occur
            shared_counter++;
        }
    };
    
    // Function that increments the counter with mutex protection
    auto safe_increment = [&shared_counter]() {
        for (int i = 0; i < 1000; ++i) {
            // Lock the mutex before accessing shared resource
            std::lock_guard<std::mutex> lock(global_mutex);
            shared_counter++;
            // Mutex automatically unlocked when lock goes out of scope
        }
    };
    
    // Demonstrate race condition (unsafe)
    std::cout << "Demonstrating race condition (unsafe):\n";
    shared_counter = 0;
    
    std::thread t1(unsafe_increment);
    std::thread t2(unsafe_increment);
    
    t1.join();
    t2.join();
    
    std::cout << "Expected count: 2000, Actual count: " << shared_counter << "\n";
    std::cout << "The count may be less than expected due to race conditions\n";
    
    // Demonstrate thread safety with mutex (safe)
    std::cout << "\nDemonstrating thread safety with mutex:\n";
    shared_counter = 0;
    
    std::thread t3(safe_increment);
    std::thread t4(safe_increment);
    
    t3.join();
    t4.join();
    
    std::cout << "Expected count: 2000, Actual count: " << shared_counter << "\n";
    std::cout << "The count should be exactly as expected with mutex protection\n";
}

/**
 * Secure credential manager with thread safety
 */
class SecureCredentialManager {
private:
    // Mutex for thread safety
    mutable std::mutex mutex_;
    
    // Credentials storage (username -> password hash)
    std::unordered_map<std::string, std::string> credentials_;
    
    // Audit log
    std::vector<std::string> audit_log_;
    
    // Random number generator for timing variation
    std::mt19937 rng_;
    std::uniform_int_distribution<> dist_{50, 150};
    
    // Add an entry to the audit log
    void addAuditLog(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        
        // Format time as string
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&now_c));
        
        // Add log entry
        audit_log_.push_back(std::string(time_str) + " - " + message);
    }
    
public:
    // Constructor
    SecureCredentialManager() : rng_(std::random_device{}()) {
        std::cout << "Secure credential manager initialized\n";
    }
    
    // Add or update credentials
    void setCredentials(const std::string& username, const std::string& password_hash) {
        // Lock the mutex to ensure thread safety
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Update credentials
        credentials_[username] = password_hash;
        
        // Log the action (without the actual password hash)
        addAuditLog("Credentials updated for user: " + username);
    }
    
    // Verify credentials (constant-time comparison to prevent timing attacks)
    bool verifyCredentials(const std::string& username, const std::string& password_hash) {
        // Use a constant-time comparison to prevent timing attacks
        bool result = false;
        
        {
            // Lock the mutex for reading credentials
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Check if user exists
            auto it = credentials_.find(username);
            if (it != credentials_.end()) {
                // Get the stored hash
                const std::string& stored_hash = it->second;
                
                // Constant-time comparison
                if (stored_hash.length() == password_hash.length()) {
                    // Initialize result to true
                    result = true;
                    
                    // Compare each character
                    for (size_t i = 0; i < stored_hash.length(); ++i) {
                        // If any character doesn't match, set result to false
                        // but continue comparing all characters to maintain constant time
                        if (stored_hash[i] != password_hash[i]) {
                            result = false;
                        }
                    }
                }
            }
        }
        
        // Add random delay to further prevent timing attacks
        std::this_thread::sleep_for(std::chrono::milliseconds(dist_(rng_)));
        
        // Log the verification attempt
        addAuditLog("Credential verification " + std::string(result ? "succeeded" : "failed") + 
                   " for user: " + username);
        
        return result;
    }
    
    // Get the audit log
    std::vector<std::string> getAuditLog() const {
        // Lock the mutex for reading the audit log
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Return a copy of the audit log
        return audit_log_;
    }
    
    // Clear credentials for a user
    void clearCredentials(const std::string& username) {
        // Lock the mutex to ensure thread safety
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Remove credentials
        credentials_.erase(username);
        
        // Log the action
        addAuditLog("Credentials cleared for user: " + username);
    }
};

/**
 * Demonstrate reader-writer lock with shared_mutex
 */
void demonstrateReaderWriterLock() {
    std::cout << "\n=== Reader-Writer Lock with shared_mutex ===\n";
    
    // Shared resource
    std::vector<std::string> sensitive_data = {"password1", "password2", "password3"};
    
    // Reader function (multiple readers can access simultaneously)
    auto reader = [&sensitive_data](int id) {
        for (int i = 0; i < 3; ++i) {
            // Acquire shared lock (multiple readers allowed)
            std::shared_lock<std::shared_mutex> lock(shared_mutex);
            
            // Read the data
            std::cout << "Reader " << id << " reading data: ";
            for (const auto& item : sensitive_data) {
                std::cout << item << " ";
            }
            std::cout << "\n";
            
            // Simulate some processing time
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Shared lock automatically released when lock goes out of scope
        }
    };
    
    // Writer function (exclusive access)
    auto writer = [&sensitive_data](int id) {
        for (int i = 0; i < 2; ++i) {
            // Acquire exclusive lock (no other readers or writers allowed)
            std::unique_lock<std::shared_mutex> lock(shared_mutex);
            
            // Modify the data
            std::cout << "Writer " << id << " modifying data\n";
            sensitive_data.push_back("new_password" + std::to_string(id) + "_" + std::to_string(i));
            
            // Simulate some processing time
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            // Exclusive lock automatically released when lock goes out of scope
        }
    };
    
    // Create reader threads
    std::vector<std::thread> reader_threads;
    for (int i = 0; i < 3; ++i) {
        reader_threads.emplace_back(reader, i);
    }
    
    // Create writer threads
    std::vector<std::thread> writer_threads;
    for (int i = 0; i < 2; ++i) {
        writer_threads.emplace_back(writer, i);
    }
    
    // Join all threads
    for (auto& t : reader_threads) {
        t.join();
    }
    for (auto& t : writer_threads) {
        t.join();
    }
    
    // Show final data
    std::cout << "Final data: ";
    for (const auto& item : sensitive_data) {
        std::cout << item << " ";
    }
    std::cout << "\n";
    
    std::cout << "Reader-writer lock allows multiple readers simultaneously\n";
    std::cout << "but ensures exclusive access for writers to prevent data corruption\n";
}

/**
 * Demonstrate atomic operations
 */
void demonstrateAtomicOperations() {
    std::cout << "\n=== Atomic Operations ===\n";
    
    // Reset the atomic counter
    access_count.store(0);
    
    // Function that increments the atomic counter
    auto increment_counter = [](int id, int iterations) {
        for (int i = 0; i < iterations; ++i) {
            // Atomic increment (thread-safe without mutex)
            access_count.fetch_add(1, std::memory_order_relaxed);
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        std::cout << "Thread " << id << " completed " << iterations << " increments\n";
    };
    
    // Create threads to increment the counter
    std::vector<std::thread> threads;
    int total_increments = 0;
    
    for (int i = 0; i < 5; ++i) {
        int iterations = 100 + i * 20;  // Different number of iterations per thread
        total_increments += iterations;
        threads.emplace_back(increment_counter, i, iterations);
    }
    
    // Join all threads
    for (auto& t : threads) {
        t.join();
    }
    
    // Check the final counter value
    std::cout << "Expected counter value: " << total_increments << "\n";
    std::cout << "Actual counter value: " << access_count.load() << "\n";
    
    std::cout << "Atomic operations provide thread safety without mutex overhead\n";
    std::cout << "and are ideal for simple operations like counters\n";
}

/**
 * Demonstrate thread-local storage
 */
void demonstrateThreadLocalStorage() {
    std::cout << "\n=== Thread-Local Storage ===\n";
    
    // Thread-local variable
    thread_local int sensitive_data = 0;
    
    // Function that uses thread-local storage
    auto thread_func = [](int id) {
        // Each thread has its own copy of sensitive_data
        sensitive_data = id * 100;  // This only affects this thread's copy
        
        std::cout << "Thread " << id << " set its sensitive_data to " << sensitive_data << "\n";
        
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Verify the data hasn't been changed by other threads
        std::cout << "Thread " << id << " still has sensitive_data = " << sensitive_data << "\n";
    };
    
    // Create threads
    std::vector<std::thread> threads;
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back(thread_func, i);
    }
    
    // Join all threads
    for (auto& t : threads) {
        t.join();
    }
    
    std::cout << "Thread-local storage prevents data races by giving each thread\n";
    std::cout << "its own private copy of the variable\n";
}

/**
 * Demonstrate condition variables for thread synchronization
 */
void demonstrateConditionVariables() {
    std::cout << "\n=== Condition Variables for Thread Synchronization ===\n";
    
    // Reset the data_ready flag
    data_ready = false;
    
    // Sensitive data to be processed
    std::string sensitive_data = "Uninitialized";
    
    // Producer thread - prepares the data
    auto producer = []() {
        // Simulate data preparation
        std::cout << "Producer: Preparing sensitive data...\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Update the data with a lock
        {
            std::lock_guard<std::mutex> lock(condition_mutex);
            sensitive_data = "SECRET_KEY_12345";
            data_ready = true;
            std::cout << "Producer: Data is ready\n";
        }
        
        // Notify waiting threads
        condition.notify_all();
    };
    
    // Consumer thread - processes the data when ready
    auto consumer = [](int id) {
        std::cout << "Consumer " << id << ": Waiting for data...\n";
        
        // Wait for data to be ready
        std::unique_lock<std::mutex> lock(condition_mutex);
        condition.wait(lock, []{ return data_ready; });
        
        // Data is ready and we have the lock
        std::cout << "Consumer " << id << ": Processing data: " << sensitive_data << "\n";
        
        // Process the data...
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Clear sensitive data when done
        if (id == 0) {  // Only one consumer should clear the data
            sensitive_data = "CLEARED";
            std::cout << "Consumer " << id << ": Cleared sensitive data\n";
        }
        
        // Lock is automatically released when it goes out of scope
    };
    
    // Create producer thread
    std::thread producer_thread(producer);
    
    // Create consumer threads
    std::vector<std::thread> consumer_threads;
    for (int i = 0; i < 3; ++i) {
        consumer_threads.emplace_back(consumer, i);
    }
    
    // Join all threads
    producer_thread.join();
    for (auto& t : consumer_threads) {
        t.join();
    }
    
    std::cout << "Condition variables allow threads to wait efficiently\n";
    std::cout << "until a specific condition is met, avoiding busy waiting\n";
}

/**
 * Demonstrate deadlock prevention
 */
void demonstrateDeadlockPrevention() {
    std::cout << "\n=== Deadlock Prevention ===\n";
    
    // Two mutexes that could cause deadlock if not careful
    std::mutex mutex1, mutex2;
    
    // Function that could cause deadlock if not implemented carefully
    auto unsafe_transfer = [&mutex1, &mutex2](bool reverse_order) {
        if (!reverse_order) {
            // Thread 1: Lock mutexes in order: mutex1 then mutex2
            std::lock_guard<std::mutex> lock1(mutex1);
            std::cout << "Thread acquired first mutex\n";
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            std::lock_guard<std::mutex> lock2(mutex2);
            std::cout << "Thread acquired second mutex\n";
            
            // Perform the operation
            std::cout << "Operation completed successfully\n";
        } else {
            // Thread 2: Lock mutexes in order: mutex2 then mutex1
            std::lock_guard<std::mutex> lock2(mutex2);
            std::cout << "Thread acquired second mutex\n";
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            std::lock_guard<std::mutex> lock1(mutex1);
            std::cout << "Thread acquired first mutex\n";
            
            // Perform the operation
            std::cout << "Operation completed successfully\n";
        }
    };
    
    // Function that prevents deadlock using std::lock
    auto safe_transfer = [&mutex1, &mutex2](bool) {
        // Lock both mutexes atomically to prevent deadlock
        std::scoped_lock lock(mutex1, mutex2);
        
        std::cout << "Thread safely acquired both mutexes\n";
        
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Perform the operation
        std::cout << "Operation completed successfully\n";
    };
    
    std::cout << "Demonstrating deadlock prevention with std::scoped_lock:\n";
    
    // Create threads using the safe transfer function
    std::thread t1(safe_transfer, false);
    std::thread t2(safe_transfer, true);
    
    // Join threads
    t1.join();
    t2.join();
    
    std::cout << "Both threads completed without deadlock\n";
    std::cout << "std::scoped_lock and std::lock prevent deadlock by acquiring\n";
    std::cout << "multiple mutexes atomically in a deadlock-free manner\n";
}

/**
 * Demonstrate thread-safe singleton pattern
 */
class SecureLogger {
private:
    // Private constructor (singleton pattern)
    SecureLogger() {
        std::cout << "SecureLogger instance created\n";
    }
    
    // Delete copy constructor and assignment operator
    SecureLogger(const SecureLogger&) = delete;
    SecureLogger& operator=(const SecureLogger&) = delete;
    
    // Mutex for thread-safe logging
    std::mutex log_mutex_;
    
    // Log storage
    std::vector<std::string> log_;
    
public:
    // Thread-safe singleton instance getter
    static SecureLogger& getInstance() {
        // C++11 guarantees thread-safe initialization of static locals
        static SecureLogger instance;
        return instance;
    }
    
    // Thread-safe log method
    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        
        // Format time as string
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&now_c));
        
        // Add log entry
        log_.push_back(std::string(time_str) + " - " + message);
    }
    
    // Get all logs
    std::vector<std::string> getLogs() const {
        std::lock_guard<std::mutex> lock(log_mutex_);
        return log_;
    }
    
    // Clear logs
    void clearLogs() {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_.clear();
    }
};

void demonstrateThreadSafeSingleton() {
    std::cout << "\n=== Thread-Safe Singleton Pattern ===\n";
    
    // Function that uses the singleton logger
    auto log_function = [](int id, int iterations) {
        for (int i = 0; i < iterations; ++i) {
            // Get the singleton instance and log a message
            SecureLogger::getInstance().log("Thread " + std::to_string(id) + 
                                          " - Log entry " + std::to_string(i));
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    // Create threads that use the logger
    std::vector<std::thread> threads;
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back(log_function, i, 10);
    }
    
    // Join all threads
    for (auto& t : threads) {
        t.join();
    }
    
    // Get and display the logs
    auto logs = SecureLogger::getInstance().getLogs();
    std::cout << "Total log entries: " << logs.size() << "\n";
    std::cout << "First few log entries:\n";
    for (size_t i = 0; i < std::min(logs.size(), size_t(5)); ++i) {
        std::cout << logs[i] << "\n";
    }
    
    std::cout << "Thread-safe singleton ensures only one instance exists\n";
    std::cout << "and provides thread-safe access to shared resources\n";
}

/**
 * Demonstrate secure credential manager with multiple threads
 */
void demonstrateSecureCredentialManagerThreadSafety() {
    std::cout << "\n=== Secure Credential Manager Thread Safety ===\n";
    
    // Create a secure credential manager
    SecureCredentialManager manager;
    
    // Add some initial credentials
    manager.setCredentials("admin", "admin_hash");
    manager.setCredentials("user1", "user1_hash");
    
    // Function that updates credentials
    auto update_credentials = [&manager](int id, const std::string& username_prefix, int iterations) {
        for (int i = 0; i < iterations; ++i) {
            std::string username = username_prefix + std::to_string(i);
            std::string password_hash = "hash_" + username + "_" + std::to_string(id);
            
            // Update credentials
            manager.setCredentials(username, password_hash);
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    // Function that verifies credentials
    auto verify_credentials = [&manager](int id, const std::string& username_prefix, int iterations) {
        for (int i = 0; i < iterations; ++i) {
            std::string username = username_prefix + std::to_string(i % 3);  // Reuse some usernames
            std::string password_hash = "hash_" + username + "_" + std::to_string(id);
            
            // Verify credentials (will mostly fail, which is expected)
            bool result = manager.verifyCredentials(username, password_hash);
            
            // Simulate some work
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    
    // Create threads for updating and verifying credentials
    std::vector<std::thread> threads;
    
    // Update threads
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back(update_credentials, i, "user", 5);
    }
    
    // Verify threads
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back(verify_credentials, i, "user", 10);
    }
    
    // Join all threads
    for (auto& t : threads) {
        t.join();
    }
    
    // Get and display the audit log
    auto audit_log = manager.getAuditLog();
    std::cout << "Total audit log entries: " << audit_log.size() << "\n";
    std::cout << "First few audit log entries:\n";
    for (size_t i = 0; i < std::min(audit_log.size(), size_t(5)); ++i) {
        std::cout << audit_log[i] << "\n";
    }
    
    std::cout << "Secure credential manager provides thread-safe access\n";
    std::cout << "to sensitive credentials and maintains an audit log\n";
}

/**
 * Demonstrate async and futures for parallel security operations
 */
void demonstrateAsyncAndFutures() {
    std::cout << "\n=== Async and Futures for Parallel Security Operations ===\n";
    
    // Function to simulate password hashing (computationally intensive)
    auto hash_password = [](const std::string& password, int strength) -> std::string {
        std::cout << "Starting password hashing with strength " << strength << "\n";
        
        // Simulate computationally intensive hashing
        std::this_thread::sleep_for(std::chrono::milliseconds(strength * 100));
        
        // Generate a "hash" (this is not a real hash function)
        std::string hash = "hash_" + password + "_" + std::to_string(strength);
        
        std::cout << "Finished password hashing with strength " << strength << "\n";
        return hash;
    };
    
    // Function to simulate file encryption (I/O intensive)
    auto encrypt_file = [](const std::string& filename, const std::string& key) -> bool {
        std::cout << "Starting encryption of file " << filename << "\n";
        
        // Simulate I/O intensive encryption
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        
        std::cout << "Finished encryption of file " << filename << "\n";
        return true;
    };
    
    // Start multiple operations in parallel using async
    std::cout << "Starting parallel security operations...\n";
    
    // Start password hashing tasks
    auto hash_future1 = std::async(std::launch::async, hash_password, "password1", 5);
    auto hash_future2 = std::async(std::launch::async, hash_password, "password2", 10);
    
    // Start file encryption tasks
    auto encrypt_future1 = std::async(std::launch::async, encrypt_file, "file1.txt", "key1");
    auto encrypt_future2 = std::async(std::launch::async, encrypt_file, "file2.txt", "key2");
    
    // Wait for and process results
    try {
        // Get password hash results
        std::string hash1 = hash_future1.get();
        std::string hash2 = hash_future2.get();
        
        std::cout << "Password hash results:\n";
        std::cout << "Hash 1: " << hash1 << "\n";
        std::cout << "Hash 2: " << hash2 << "\n";
        
        // Get file encryption results
        bool encrypt_result1 = encrypt_future1.get();
        bool encrypt_result2 = encrypt_future2.get();
        
        std::cout << "File encryption results:\n";
        std::cout << "File 1: " << (encrypt_result1 ? "Success" : "Failure") << "\n";
        std::cout << "File 2: " << (encrypt_result2 ? "Success" : "Failure") << "\n";
    } catch (const std::exception& e) {
        std::cout << "Error in parallel operations: " << e.what() << "\n";
    }
    
    std::cout << "Async and futures allow parallel execution of intensive operations\n";
    std::cout << "while providing structured error handling and result retrieval\n";
}

int main() {
    std::cout << "=== Thread Safety in C++: Cybersecurity Perspective ===\n";
    
    // Demonstrate basic thread safety with mutex
    demonstrateBasicThreadSafety();
    
    // Demonstrate reader-writer lock
    demonstrateReaderWriterLock();
    
    // Demonstrate atomic operations
    demonstrateAtomicOperations();
    
    // Demonstrate thread-local storage
    demonstrateThreadLocalStorage();
    
    // Demonstrate condition variables
    demonstrateConditionVariables();
    
    // Demonstrate deadlock prevention
    demonstrateDeadlockPrevention();
    
    // Demonstrate thread-safe singleton pattern
    demonstrateThreadSafeSingleton();
    
    // Demonstrate secure credential manager thread safety
    demonstrateSecureCredentialManagerThreadSafety();
    
    // Demonstrate async and futures
    demonstrateAsyncAndFutures();
    
    std::cout << "\n=== Security Best Practices for Thread Safety ===\n";
    std::cout << "1. Use appropriate synchronization mechanisms for shared resources\n";
    std::cout << "2. Prefer higher-level abstractions (atomic, futures) when possible\n";
    std::cout << "3. Be aware of deadlock risks and use techniques to prevent them\n";
    std::cout << "4. Use thread-local storage for thread-specific sensitive data\n";
    std::cout << "5. Implement constant-time operations for security-critical code\n";
    std::cout << "6. Maintain audit logs for security-relevant operations\n";
    std::cout << "7. Use RAII for resource management in multi-threaded code\n";
    std::cout << "8. Consider thread safety in singleton and shared resource designs\n";
    
    return 0;
}

