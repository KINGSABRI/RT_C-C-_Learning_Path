/**
 * Smart Pointers in C++ - Cybersecurity Perspective
 * 
 * This program demonstrates smart pointers in C++ with a focus on
 * security implications and best practices.
 */

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <stdexcept>

// Forward declarations
class Resource;
class SecureResource;
class ResourceManager;

/**
 * Basic resource class to demonstrate memory management
 */
class Resource {
private:
    std::string name;
    size_t size;
    bool is_sensitive;
    
public:
    // Constructor
    Resource(const std::string& name, size_t size, bool is_sensitive = false)
        : name(name), size(size), is_sensitive(is_sensitive) {
        std::cout << "Resource created: " << name << " (" << size << " bytes)" << std::endl;
    }
    
    // Destructor
    virtual ~Resource() {
        std::cout << "Resource destroyed: " << name << std::endl;
    }
    
    // Getters
    std::string getName() const { return name; }
    size_t getSize() const { return size; }
    bool isSensitive() const { return is_sensitive; }
    
    // Simulate using the resource
    virtual void use() const {
        std::cout << "Using resource: " << name << std::endl;
    }
};

/**
 * Secure resource class with additional security features
 */
class SecureResource : public Resource {
private:
    void* sensitive_data;
    
    // Helper to securely wipe memory
    void wipeMemory() {
        if (sensitive_data) {
            // Zero out memory for security
            memset(sensitive_data, 0, getSize());
        }
    }
    
public:
    // Constructor
    SecureResource(const std::string& name, size_t size)
        : Resource(name, size, true) {
        // Allocate memory for sensitive data
        sensitive_data = malloc(size);
        if (!sensitive_data) {
            throw std::bad_alloc();
        }
        
        // Initialize memory to zero
        memset(sensitive_data, 0, size);
        
        std::cout << "Secure resource initialized with zeroed memory" << std::endl;
    }
    
    // Destructor
    ~SecureResource() override {
        std::cout << "Securely wiping sensitive data before destruction" << std::endl;
        wipeMemory();
        free(sensitive_data);
        sensitive_data = nullptr;
    }
    
    // Override use method
    void use() const override {
        std::cout << "Using secure resource: " << getName() << " (with extra protection)" << std::endl;
    }
    
    // Store data in the secure memory
    void storeData(const void* data, size_t data_size) {
        if (data_size > getSize()) {
            throw std::runtime_error("Data size exceeds allocated memory");
        }
        
        memcpy(sensitive_data, data, data_size);
        std::cout << "Data stored securely in " << getName() << std::endl;
    }
    
    // Clear the secure memory
    void clearData() {
        wipeMemory();
        std::cout << "Secure data cleared from " << getName() << std::endl;
    }
};

/**
 * Custom deleter for secure resources
 */
struct SecureDeleter {
    void operator()(Resource* resource) const {
        std::cout << "Custom secure deleter called for: " << resource->getName() << std::endl;
        
        // Additional security measures before deletion
        if (resource->isSensitive()) {
            std::cout << "Performing additional security cleanup for sensitive resource" << std::endl;
            // In a real application, this might involve more sophisticated cleanup
        }
        
        delete resource;
    }
};

/**
 * Resource manager using smart pointers
 */
class ResourceManager {
private:
    std::vector<std::shared_ptr<Resource>> resources;
    
public:
    // Add a resource to the manager
    void addResource(std::shared_ptr<Resource> resource) {
        resources.push_back(resource);
        std::cout << "Resource added to manager: " << resource->getName() << std::endl;
    }
    
    // Get a resource by name
    std::shared_ptr<Resource> getResource(const std::string& name) {
        auto it = std::find_if(resources.begin(), resources.end(),
                              [&name](const std::shared_ptr<Resource>& res) {
                                  return res->getName() == name;
                              });
        
        if (it != resources.end()) {
            return *it;
        }
        
        return nullptr;
    }
    
    // Use all resources
    void useAllResources() const {
        std::cout << "Using all managed resources:" << std::endl;
        for (const auto& resource : resources) {
            resource->use();
        }
    }
    
    // Get count of managed resources
    size_t getResourceCount() const {
        return resources.size();
    }
    
    // Clear all resources
    void clearResources() {
        std::cout << "Clearing all resources from manager" << std::endl;
        resources.clear();
    }
};

/**
 * Demonstrate unique_ptr usage
 */
void demonstrateUniquePtr() {
    std::cout << "\n=== std::unique_ptr Demonstration ===\n";
    
    // Create a unique_ptr to a Resource
    std::cout << "Creating unique_ptr to a Resource:\n";
    std::unique_ptr<Resource> resource1 = std::make_unique<Resource>("ConfigFile", 1024);
    
    // Use the resource
    resource1->use();
    
    // Create a unique_ptr with a custom deleter
    std::cout << "\nCreating unique_ptr with custom deleter:\n";
    std::unique_ptr<Resource, SecureDeleter> resource2(
        new Resource("PasswordFile", 512, true)
    );
    
    // Use the resource
    resource2->use();
    
    // Transfer ownership with std::move
    std::cout << "\nTransferring ownership with std::move:\n";
    std::unique_ptr<Resource> resource3 = std::make_unique<Resource>("LogFile", 2048);
    std::cout << "Before move, resource3 points to: " << resource3->getName() << std::endl;
    
    std::unique_ptr<Resource> resource4 = std::move(resource3);
    std::cout << "After move, resource4 points to: " << resource4->getName() << std::endl;
    
    if (resource3 == nullptr) {
        std::cout << "resource3 is now nullptr after move" << std::endl;
    }
    
    // Unique ownership prevents double-free and use-after-free
    std::cout << "\nUnique ownership prevents memory safety issues:\n";
    std::cout << "- Double-free: Prevented because only one pointer owns the resource\n";
    std::cout << "- Use-after-free: Prevented because moved-from pointers are set to nullptr\n";
    std::cout << "- Memory leaks: Prevented by automatic cleanup in destructor\n";
    
    // resource3->use();  // This would cause a runtime error (nullptr dereference)
    
    std::cout << "\nAt the end of this function, all unique_ptrs will be automatically destroyed\n";
}

/**
 * Demonstrate shared_ptr usage
 */
void demonstrateSharedPtr() {
    std::cout << "\n=== std::shared_ptr Demonstration ===\n";
    
    // Create a shared_ptr to a Resource
    std::cout << "Creating shared_ptr to a Resource:\n";
    std::shared_ptr<Resource> resource1 = std::make_shared<Resource>("SharedConfig", 1024);
    
    std::cout << "Initial reference count: " << resource1.use_count() << std::endl;
    
    // Create another shared_ptr pointing to the same resource
    std::cout << "\nCreating another shared_ptr to the same resource:\n";
    std::shared_ptr<Resource> resource2 = resource1;
    
    std::cout << "Reference count after sharing: " << resource1.use_count() << std::endl;
    
    // Create a shared_ptr with a custom deleter
    std::cout << "\nCreating shared_ptr with custom deleter:\n";
    std::shared_ptr<Resource> resource3(
        new Resource("SharedSecretKey", 256, true),
        SecureDeleter()
    );
    
    std::cout << "Reference count for resource3: " << resource3.use_count() << std::endl;
    
    // Create a resource manager and add resources
    std::cout << "\nAdding resources to a manager:\n";
    ResourceManager manager;
    
    manager.addResource(resource1);  // Increases reference count
    manager.addResource(resource3);
    
    std::cout << "Reference count after adding to manager: " << resource1.use_count() << std::endl;
    
    // Use the resources through the manager
    manager.useAllResources();
    
    // Clear one reference
    std::cout << "\nClearing one reference:\n";
    resource1.reset();
    std::cout << "Reference count after resetting resource1: " << resource2.use_count() << std::endl;
    
    // Clear the manager, which will release its references
    std::cout << "\nClearing the resource manager:\n";
    manager.clearResources();
    
    std::cout << "Reference count after clearing manager: " << resource2.use_count() << std::endl;
    
    std::cout << "\nShared ownership benefits:\n";
    std::cout << "- Resources can be shared safely between multiple owners\n";
    std::cout << "- Automatic cleanup occurs when the last reference is gone\n";
    std::cout << "- Reference counting prevents premature destruction\n";
}

/**
 * Demonstrate weak_ptr usage
 */
void demonstrateWeakPtr() {
    std::cout << "\n=== std::weak_ptr Demonstration ===\n";
    
    // Create a shared_ptr to a Resource
    std::shared_ptr<Resource> shared = std::make_shared<Resource>("CacheData", 4096);
    std::cout << "Shared_ptr created with reference count: " << shared.use_count() << std::endl;
    
    // Create a weak_ptr from the shared_ptr
    std::weak_ptr<Resource> weak = shared;
    std::cout << "Weak_ptr created, shared reference count remains: " << shared.use_count() << std::endl;
    
    // Use the weak_ptr to access the resource
    std::cout << "\nUsing weak_ptr to access the resource:\n";
    if (auto resource = weak.lock()) {
        std::cout << "Successfully locked weak_ptr to access: " << resource->getName() << std::endl;
        std::cout << "Reference count during lock: " << shared.use_count() << std::endl;
    } else {
        std::cout << "Failed to lock weak_ptr (resource no longer exists)" << std::endl;
    }
    
    // Demonstrate expired weak_ptr
    std::cout << "\nDemonstrating expired weak_ptr:\n";
    std::cout << "Is weak_ptr expired? " << (weak.expired() ? "Yes" : "No") << std::endl;
    
    // Reset the shared_ptr, which will destroy the resource
    std::cout << "\nResetting the shared_ptr:\n";
    shared.reset();
    std::cout << "Shared_ptr reset, resource should be destroyed" << std::endl;
    
    // Try to use the weak_ptr again
    std::cout << "\nTrying to use weak_ptr after shared_ptr is reset:\n";
    std::cout << "Is weak_ptr expired? " << (weak.expired() ? "Yes" : "No") << std::endl;
    
    if (auto resource = weak.lock()) {
        std::cout << "Successfully locked weak_ptr (shouldn't happen)" << std::endl;
    } else {
        std::cout << "Failed to lock weak_ptr as expected (resource no longer exists)" << std::endl;
    }
    
    std::cout << "\nWeak_ptr benefits for security:\n";
    std::cout << "- Prevents dangling pointer issues\n";
    std::cout << "- Allows checking if a resource still exists before using it\n";
    std::cout << "- Breaks reference cycles to prevent memory leaks\n";
    std::cout << "- Doesn't keep resources alive when they're no longer needed\n";
}

/**
 * Demonstrate secure resource management
 */
void demonstrateSecureResourceManagement() {
    std::cout << "\n=== Secure Resource Management ===\n";
    
    try {
        // Create a secure resource with unique_ptr
        std::cout << "Creating secure resource with unique_ptr:\n";
        auto secure_resource = std::make_unique<SecureResource>("EncryptionKey", 128);
        
        // Store sensitive data
        const char* sensitive_data = "SECRET_KEY_12345";
        secure_resource->storeData(sensitive_data, strlen(sensitive_data) + 1);
        
        // Use the resource
        secure_resource->use();
        
        // Explicitly clear the data when done with it
        secure_resource->clearData();
        
        // Resource will be automatically destroyed and memory securely wiped
        std::cout << "\nLetting unique_ptr go out of scope:\n";
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    // Demonstrate secure resource sharing
    std::cout << "\nDemonstrating secure resource sharing:\n";
    
    // Create a shared secure resource
    auto shared_secure = std::shared_ptr<SecureResource>(
        new SecureResource("SharedKey", 256),
        [](SecureResource* resource) {
            std::cout << "Custom deleter for shared secure resource" << std::endl;
            delete resource;
        }
    );
    
    // Store data in the shared resource
    const char* shared_data = "SHARED_SECRET_DATA";
    shared_secure->storeData(shared_data, strlen(shared_data) + 1);
    
    // Create a resource manager for secure resources
    ResourceManager secure_manager;
    secure_manager.addResource(shared_secure);
    
    // Use the resource through the manager
    secure_manager.useAllResources();
    
    // Clear the manager, but the resource will still exist due to our shared_ptr
    secure_manager.clearResources();
    std::cout << "Manager cleared, but resource still exists" << std::endl;
    
    // Use the resource directly
    shared_secure->use();
    
    // Explicitly clear sensitive data
    shared_secure->clearData();
    
    // Reset the shared_ptr, which will trigger the custom deleter
    std::cout << "\nResetting shared_ptr to trigger secure cleanup:\n";
    shared_secure.reset();
}

/**
 * Demonstrate common memory safety issues and how smart pointers prevent them
 */
void demonstrateMemorySafetyIssues() {
    std::cout << "\n=== Memory Safety Issues Prevention ===\n";
    
    // 1. Memory leaks
    std::cout << "1. Preventing memory leaks:\n";
    {
        // Raw pointer approach (potential memory leak)
        std::cout << "Raw pointer approach (commented out to prevent actual leak):\n";
        // Resource* raw_resource = new Resource("LeakedResource", 1024);
        // If we forget to delete or an exception occurs, we have a leak
        
        // Smart pointer approach (automatic cleanup)
        std::cout << "Smart pointer approach (automatic cleanup):\n";
        auto smart_resource = std::make_unique<Resource>("SafeResource", 1024);
        // No need to manually delete, even if exceptions occur
    }
    
    // 2. Use-after-free
    std::cout << "\n2. Preventing use-after-free:\n";
    {
        // Raw pointer approach (potential use-after-free)
        std::cout << "Raw pointer approach (commented out to prevent actual error):\n";
        /*
        Resource* raw_resource = new Resource("DangerousResource", 512);
        delete raw_resource;  // Resource is freed
        raw_resource->use();  // Use-after-free! Undefined behavior
        */
        
        // Smart pointer approach (prevents use-after-free)
        std::cout << "Smart pointer approach (prevents use-after-free):\n";
        auto smart_resource = std::make_unique<Resource>("SafeResource", 512);
        smart_resource.reset();  // Resource is freed and pointer is set to nullptr
        
        if (smart_resource == nullptr) {
            std::cout << "Smart pointer is null after reset, preventing use-after-free" << std::endl;
        }
    }
    
    // 3. Double-free
    std::cout << "\n3. Preventing double-free:\n";
    {
        // Raw pointer approach (potential double-free)
        std::cout << "Raw pointer approach (commented out to prevent actual error):\n";
        /*
        Resource* raw_resource = new Resource("RiskyResource", 256);
        delete raw_resource;  // First delete
        delete raw_resource;  // Double-free! Undefined behavior
        */
        
        // Smart pointer approach (prevents double-free)
        std::cout << "Smart pointer approach (prevents double-free):\n";
        auto smart_resource = std::make_unique<Resource>("SafeResource", 256);
        smart_resource.reset();  // First delete
        smart_resource.reset();  // No-op, already nullptr
        std::cout << "Second reset on null smart pointer is safe" << std::endl;
    }
    
    // 4. Dangling pointers
    std::cout << "\n4. Preventing dangling pointers:\n";
    {
        // Raw pointer approach (potential dangling pointer)
        std::cout << "Raw pointer approach (commented out to prevent actual error):\n";
        /*
        Resource* raw_resource1 = new Resource("Resource1", 128);
        Resource* raw_resource2 = raw_resource1;  // Both point to the same resource
        delete raw_resource1;  // Resource is freed
        raw_resource1 = nullptr;  // This pointer is nulled
        raw_resource2->use();  // Dangling pointer! Undefined behavior
        */
        
        // Smart pointer approach with shared_ptr (prevents dangling pointers)
        std::cout << "Smart pointer approach with shared_ptr:\n";
        auto shared_resource1 = std::make_shared<Resource>("SharedResource", 128);
        auto shared_resource2 = shared_resource1;  // Both share ownership
        
        shared_resource1.reset();  // First shared_ptr gives up ownership
        std::cout << "First shared_ptr reset, but resource still exists" << std::endl;
        
        // Second shared_ptr still safely owns the resource
        shared_resource2->use();
        
        // Smart pointer approach with weak_ptr (safe observation)
        std::cout << "\nSmart pointer approach with weak_ptr:\n";
        auto shared_resource3 = std::make_shared<Resource>("ObservedResource", 128);
        std::weak_ptr<Resource> weak_resource = shared_resource3;
        
        shared_resource3.reset();  // Resource is freed
        std::cout << "Shared_ptr reset, resource is freed" << std::endl;
        
        // Check if resource still exists before using
        if (auto locked = weak_resource.lock()) {
            std::cout << "Resource still exists (shouldn't happen)" << std::endl;
        } else {
            std::cout << "Weak_ptr correctly detected that resource no longer exists" << std::endl;
        }
    }
}

int main() {
    std::cout << "=== Smart Pointers in C++: Cybersecurity Perspective ===\n";
    
    // Demonstrate unique_ptr
    demonstrateUniquePtr();
    
    // Demonstrate shared_ptr
    demonstrateSharedPtr();
    
    // Demonstrate weak_ptr
    demonstrateWeakPtr();
    
    // Demonstrate secure resource management
    demonstrateSecureResourceManagement();
    
    // Demonstrate memory safety issues prevention
    demonstrateMemorySafetyIssues();
    
    std::cout << "\n=== Security Benefits of Smart Pointers ===\n";
    std::cout << "1. Automatic resource management prevents memory leaks\n";
    std::cout << "2. Ownership semantics prevent use-after-free and double-free errors\n";
    std::cout << "3. Null checking prevents null pointer dereferences\n";
    std::cout << "4. Custom deleters enable secure cleanup of sensitive resources\n";
    std::cout << "5. Weak pointers prevent dangling pointer issues\n";
    std::cout << "6. Type safety prevents pointer type confusion\n";
    
    return 0;
}

