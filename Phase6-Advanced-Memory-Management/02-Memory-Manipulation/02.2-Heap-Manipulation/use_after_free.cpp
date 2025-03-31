/**
 * @file use_after_free.cpp
 * @brief Demonstrates use-after-free vulnerabilities and exploitation techniques
 *
 * This file demonstrates how use-after-free vulnerabilities occur and how they
 * can be exploited. It includes examples of vulnerable code, exploitation techniques,
 * and mitigation strategies. Use-after-free occurs when a program continues to use
 * a pointer after the memory it points to has been freed.
 *
 * WARNING: This code intentionally contains vulnerabilities for educational purposes.
 * Do not use these techniques on systems without proper authorization.
 *
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 use_after_free.cpp -o use_after_free.exe
 *
 * Red Team Applications:
 * - Exploiting vulnerable applications to gain code execution
 * - Manipulating object-oriented programs through dangling pointers
 * - Understanding memory corruption vulnerabilities
 * - Developing custom exploits for penetration testing
 */

#include <iostream>
#include <cstring>
#include <vector>
#include <functional>
#include <memory>

// Class with a virtual function to demonstrate vtable hijacking
class Base
{
public:
    Base(const char *name)
    {
        strncpy(this->name, name, sizeof(this->name) - 1);
        this->name[sizeof(this->name) - 1] = '\0';
    }

    virtual ~Base()
    {
        std::cout << "Base destructor called for " << name << std::endl;
    }

    virtual void doSomething()
    {
        std::cout << "Base::doSomething() called for " << name << std::endl;
    }

    char name[32];
};

// Derived class to demonstrate polymorphism
class Derived : public Base
{
public:
    Derived(const char *name) : Base(name) {}

    virtual void doSomething() override
    {
        std::cout << "Derived::doSomething() called for " << name << std::endl;
    }
};

// Malicious class to demonstrate vtable hijacking
class Malicious : public Base
{
public:
    Malicious(const char *name) : Base(name) {}

    virtual void doSomething() override
    {
        std::cout << "!!! MALICIOUS CODE EXECUTED !!!" << std::endl;
        std::cout << "In a real exploit, this could execute arbitrary code." << std::endl;
    }
};

// Function prototypes
void demonstrate_basic_uaf();
void demonstrate_object_uaf();
void demonstrate_vtable_hijacking();
void demonstrate_mitigation();

/**
 * @brief Main function that demonstrates different aspects of use-after-free
 */
int main()
{
    std::cout << "=== Use-After-Free Demonstration ===" << std::endl;
    std::cout << std::endl;

    // Demonstrate basic use-after-free
    std::cout << "1. Basic Use-After-Free:" << std::endl;
    demonstrate_basic_uaf();
    std::cout << std::endl;

    // Demonstrate object-oriented use-after-free
    std::cout << "2. Object-Oriented Use-After-Free:" << std::endl;
    demonstrate_object_uaf();
    std::cout << std::endl;

    // Demonstrate vtable hijacking
    std::cout << "3. Virtual Table (vtable) Hijacking:" << std::endl;
    demonstrate_vtable_hijacking();
    std::cout << std::endl;

    // Demonstrate mitigation techniques
    std::cout << "4. Mitigation Techniques:" << std::endl;
    demonstrate_mitigation();

    return 0;
}

/**
 * @brief Demonstrates a basic use-after-free vulnerability
 */
void demonstrate_basic_uaf()
{
    // Allocate memory
    char *buffer = new char[16];

    // Initialize the buffer
    strcpy(buffer, "Hello, world!");
    std::cout << "Original buffer at " << static_cast<void *>(buffer) << ": " << buffer << std::endl;

    // Free the memory
    std::cout << "Freeing the buffer..." << std::endl;
    delete[] buffer;

    // Use after free (dangerous!)
    std::cout << "Use-after-free (undefined behavior):" << std::endl;
    std::cout << "buffer still contains: " << buffer << std::endl;

    // Allocate new memory that might reuse the freed space
    char *new_buffer = new char[16];
    strcpy(new_buffer, "New content!");
    std::cout << "New buffer at " << static_cast<void *>(new_buffer) << ": " << new_buffer << std::endl;

    // The original pointer might now point to the new data
    std::cout << "Original buffer now contains: " << buffer << std::endl;

    if (buffer == new_buffer)
    {
        std::cout << "The memory has been reused!" << std::endl;
    }
    else
    {
        std::cout << "The memory has not been reused in this case." << std::endl;
        std::cout << "In a real-world scenario, memory reuse depends on the allocator's behavior." << std::endl;
    }

    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker could allocate memory after the free" << std::endl;
    std::cout << "2. This new allocation could contain attacker-controlled data" << std::endl;
    std::cout << "3. When the dangling pointer is used, it operates on the attacker's data" << std::endl;

    // Clean up
    delete[] new_buffer;
    // Don't delete buffer again - it's already been freed
}

/**
 * @brief Demonstrates use-after-free with objects
 */
void demonstrate_object_uaf()
{
    // Create a vector of Base pointers
    std::vector<Base *> objects;

    // Add some objects
    objects.push_back(new Base("Object 1"));
    objects.push_back(new Derived("Object 2"));

    // Use the objects
    std::cout << "Using objects:" << std::endl;
    for (auto obj : objects)
    {
        obj->doSomething();
    }

    // Free one of the objects
    std::cout << "Freeing Object 1..." << std::endl;
    delete objects[0];

    // The pointer in the vector is now dangling
    // Use after free (dangerous!)
    std::cout << "Use-after-free with objects (undefined behavior):" << std::endl;
    objects[0]->doSomething(); // This is using a dangling pointer!

    // Allocate a new object that might reuse the freed memory
    Base *new_object = new Base("New Object");
    std::cout << "Created new object at " << new_object << std::endl;

    // The dangling pointer might now point to the new object
    std::cout << "Using dangling pointer again:" << std::endl;
    objects[0]->doSomething();

    std::cout << "In a real exploit scenario:" << std::endl;
    std::cout << "1. An attacker could allocate an object after the free" << std::endl;
    std::cout << "2. This new object could have different behavior" << std::endl;
    std::cout << "3. When the dangling pointer is used, it operates on the attacker's object" << std::endl;

    // Clean up
    delete new_object;
    delete objects[1];
    // Don't delete objects[0] again - it's already been freed
}

/**
 * @brief Demonstrates vtable hijacking through use-after-free
 */
void demonstrate_vtable_hijacking()
{
    // Create a Base object
    Base *obj = new Base("Victim");

    // Use the object
    std::cout << "Using original object:" << std::endl;
    obj->doSomething();

    // Free the object
    std::cout << "Freeing the object..." << std::endl;
    delete obj;

    // Allocate a Malicious object that might reuse the freed memory
    Malicious *malicious = new Malicious("Attacker");
    std::cout << "Created malicious object at " << malicious << std::endl;

    // In a real exploit, the attacker would try to ensure the malicious object
    // occupies the same memory as the freed object

    // Use the dangling pointer (dangerous!)
    std::cout << "Using dangling pointer (undefined behavior):" << std::endl;
    if (obj == reinterpret_cast<Base *>(malicious))
    {
        std::cout << "Memory has been reused - vtable hijacking possible!" << std::endl;
        obj->doSomething(); // This might call Malicious::doSomething()
    }
    else
    {
        std::cout << "Memory has not been reused in this case." << std::endl;
        std::cout << "In a real-world scenario, an attacker would use heap spraying" << std::endl;
        std::cout << "or other techniques to increase the likelihood of memory reuse." << std::endl;

        // For demonstration purposes, let's pretend the memory was reused
        std::cout << "For demonstration, let's simulate vtable hijacking:" << std::endl;
        malicious->doSomething();
    }

    std::cout << "How vtable hijacking works:" << std::endl;
    std::cout << "1. Objects with virtual functions contain a pointer to a virtual table (vtable)" << std::endl;
    std::cout << "2. The vtable contains pointers to the virtual functions" << std::endl;
    std::cout << "3. When a virtual function is called, the program looks up the function in the vtable" << std::endl;
    std::cout << "4. If an attacker can control the object's memory, they can replace the vtable pointer" << std::endl;
    std::cout << "5. This can redirect virtual function calls to attacker-controlled code" << std::endl;

    // Clean up
    delete malicious;
    // Don't delete obj again - it's already been freed
}

/**
 * @brief Demonstrates mitigation techniques for use-after-free vulnerabilities
 */
void demonstrate_mitigation()
{
    std::cout << "1. Using smart pointers:" << std::endl;

    // Using unique_ptr
    std::cout << "   - std::unique_ptr prevents use-after-free by automatically freeing memory:" << std::endl;
    {
        std::unique_ptr<Base> safe_obj = std::make_unique<Base>("Safe Object");
        safe_obj->doSomething();

        // No need to delete - automatically freed when out of scope
        std::cout << "   - Object is automatically freed when unique_ptr goes out of scope" << std::endl;
    }

    // Using shared_ptr
    std::cout << "   - std::shared_ptr manages object lifetime through reference counting:" << std::endl;
    {
        std::shared_ptr<Base> shared_obj = std::make_shared<Base>("Shared Object");

        {
            // Create another pointer to the same object
            std::shared_ptr<Base> another_pointer = shared_obj;
            std::cout << "   - Object has " << shared_obj.use_count() << " references" << std::endl;

            // This scope ends, but the object is not freed yet
        }

        std::cout << "   - Object now has " << shared_obj.use_count() << " reference" << std::endl;
        shared_obj->doSomething();

        // Object is freed when the last shared_ptr is destroyed
    }

    std::cout << std::endl;
    std::cout << "2. Using null pointers after free:" << std::endl;
    {
        Base *obj = new Base("To Be Nulled");
        obj->doSomething();

        delete obj;
        obj = nullptr; // Set to nullptr after freeing

        std::cout << "   - Checking for nullptr before use:" << std::endl;
        if (obj != nullptr)
        {
            obj->doSomething();
        }
        else
        {
            std::cout << "   - Pointer is null, avoiding use-after-free" << std::endl;
        }
    }

    std::cout << std::endl;
    std::cout << "3. Other mitigation techniques:" << std::endl;
    std::cout << "   - Memory allocators with security features (e.g., delayed reuse)" << std::endl;
    std::cout << "   - Address sanitizers (e.g., AddressSanitizer)" << std::endl;
    std::cout << "   - Static analysis tools to detect potential use-after-free" << std::endl;
    std::cout << "   - Secure coding practices and code reviews" << std::endl;
    std::cout << "   - Object pools with validation" << std::endl;
}
