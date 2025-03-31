/**
 * string_obfuscation.cpp
 * 
 * This module demonstrates various string obfuscation techniques used to
 * evade signature-based detection in AV/EDR solutions.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is for learning about security concepts.
 * Using these techniques against systems without authorization is illegal.
 */

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <windows.h>

/**
 * @brief Simple XOR encryption for strings
 * 
 * XOR encryption is a basic technique used to obfuscate strings.
 * It's simple but effective against basic signature detection.
 */
class XorObfuscator {
private:
    char key;

public:
    XorObfuscator(char k) : key(k) {}
    
    // Encrypt a string using XOR
    std::string encrypt(const std::string& input) {
        std::string result = input;
        for (char& c : result) {
            c ^= key;
        }
        return result;
    }
    
    // Decrypt a string using XOR (same operation as encrypt)
    std::string decrypt(const std::string& input) {
        return encrypt(input); // XOR is its own inverse
    }
};

/**
 * @brief Demonstrates XOR string obfuscation
 */
void demonstrateXorObfuscation() {
    std::cout << "=== XOR String Obfuscation ===" << std::endl;
    
    const char key = 0x5A; // XOR key
    XorObfuscator obfuscator(key);
    
    // Sensitive strings that might trigger AV
    std::string sensitiveString = "CreateRemoteThread";
    std::string obfuscatedString = obfuscator.encrypt(sensitiveString);
    
    std::cout << "Original string: " << sensitiveString << std::endl;
    std::cout << "Obfuscated string (hex): ";
    for (char c : obfuscatedString) {
        printf("\\x%02X", static_cast<unsigned char>(c));
    }
    std::cout << std::endl;
    
    std::cout << "Deobfuscated string: " << obfuscator.decrypt(obfuscatedString) << std::endl;
    std::cout << std::endl;
    
    // Example of how to use in code
    std::cout << "Example usage in code:" << std::endl;
    std::cout << R"(
    // Define obfuscated string
    const char obfuscatedString[] = { 0x19, 0x3F, 0x2E, 0x26, 0x3B, 0x2E, 0x13, 0x2E, 0x28, 0x29, 0x3B, 0x2E, 0x11, 0x27, 0x3F, 0x2E, 0x26, 0x2D, 0x00 };
    
    // Function to deobfuscate at runtime
    char* deobfuscate(const char* input, char key) {
        size_t len = strlen(input);
        char* output = new char[len + 1];
        for (size_t i = 0; i < len; i++) {
            output[i] = input[i] ^ key;
        }
        output[len] = '\0';
        return output;
    }
    
    // Use the function at runtime
    char* functionName = deobfuscate(obfuscatedString, 0x5A);
    FARPROC functionAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), functionName);
    delete[] functionName; // Clean up
    )" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates character splitting technique
 * 
 * This technique splits strings into individual characters or
 * smaller chunks to avoid signature detection.
 */
void demonstrateCharSplitting() {
    std::cout << "=== Character Splitting Technique ===" << std::endl;
    
    std::string sensitiveString = "VirtualAllocEx";
    
    std::cout << "Original string: " << sensitiveString << std::endl;
    std::cout << "Character splitting example:" << std::endl;
    std::cout << R"(
    // Instead of:
    LPVOID buffer = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Use:
    char str[] = {
        'V', 'i', 'r', 't', 'u', 'a', 'l',
        'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0'
    };
    
    typedef LPVOID (WINAPI *pVirtualAllocEx)(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );
    
    pVirtualAllocEx funcPtr = (pVirtualAllocEx)GetProcAddress(
        GetModuleHandle("kernel32.dll"), str);
    
    LPVOID buffer = funcPtr(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    )" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates stack string construction
 * 
 * This technique constructs strings on the stack at runtime
 * to avoid having them in the binary.
 */
void demonstrateStackConstruction() {
    std::cout << "=== Stack String Construction ===" << std::endl;
    
    std::cout << "Example of stack string construction:" << std::endl;
    std::cout << R"(
    // Construct the string "CreateRemoteThread" on the stack
    char functionName[18];
    functionName[0] = 'C';
    functionName[1] = 'r';
    functionName[2] = 'e';
    functionName[3] = 'a';
    functionName[4] = 't';
    functionName[5] = 'e';
    functionName[6] = 'R';
    functionName[7] = 'e';
    functionName[8] = 'm';
    functionName[9] = 'o';
    functionName[10] = 't';
    functionName[11] = 'e';
    functionName[12] = 'T';
    functionName[13] = 'h';
    functionName[14] = 'r';
    functionName[15] = 'e';
    functionName[16] = 'a';
    functionName[17] = 'd';
    functionName[18] = '\0';
    
    // Use the constructed string
    FARPROC functionAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), functionName);
    )" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates string encoding with base64
 */
void demonstrateBase64Encoding() {
    std::cout << "=== Base64 Encoding ===" << std::endl;
    
    std::cout << "Example of base64 encoding:" << std::endl;
    std::cout << "Original: CreateRemoteThread" << std::endl;
    std::cout << "Base64 encoded: Q3JlYXRlUmVtb3RlVGhyZWFk" << std::endl;
    
    std::cout << R"(
    // Base64 decode function (simplified)
    std::string base64_decode(const std::string& encoded) {
        // Implementation omitted for brevity
        // Many libraries provide this functionality
    }
    
    // Usage
    std::string encoded = "Q3JlYXRlUmVtb3RlVGhyZWFk";
    std::string functionName = base64_decode(encoded);
    FARPROC functionAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), functionName.c_str());
    )" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates string encryption with AES
 */
void demonstrateAESEncryption() {
    std::cout << "=== AES Encryption ===" << std::endl;
    
    std::cout << "For stronger obfuscation, strings can be encrypted with AES or other algorithms." << std::endl;
    std::cout << "This requires including a decryption routine in your code." << std::endl;
    
    std::cout << R"(
    // Example using Windows Crypto API (pseudocode)
    // Actual implementation would be more complex
    
    // Encrypted string (pre-computed)
    unsigned char encryptedData[] = { 0x7B, 0x8A, ... }; // AES encrypted "CreateRemoteThread"
    unsigned char key[] = { 0x12, 0x34, ... }; // Encryption key
    unsigned char iv[] = { 0xAB, 0xCD, ... }; // Initialization vector
    
    // Decrypt at runtime
    char* decryptedString = AESDecrypt(encryptedData, sizeof(encryptedData), key, iv);
    
    // Use the decrypted string
    FARPROC functionAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), decryptedString);
    
    // Clean up
    SecureZeroMemory(decryptedString, strlen(decryptedString));
    free(decryptedString);
    )" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates API hashing technique
 * 
 * Instead of storing API names, store their hash values and
 * compute hashes at runtime to find the right function.
 */
void demonstrateAPIHashing() {
    std::cout << "=== API Hashing ===" << std::endl;
    
    std::cout << "API hashing avoids storing function names entirely:" << std::endl;
    std::cout << R"(
    // Simple hash function
    DWORD hashFunction(const char* str) {
        DWORD hash = 0;
        while (*str) {
            hash = (hash << 5) + hash + *str++;
        }
        return hash;
    }
    
    // Find function by hash
    FARPROC getFunctionByHash(HMODULE module, DWORD targetHash) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        DWORD* functions = (DWORD*)((BYTE*)module + exportDir->AddressOfFunctions);
        DWORD* names = (DWORD*)((BYTE*)module + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)module + exportDir->AddressOfNameOrdinals);
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* functionName = (const char*)((BYTE*)module + names[i]);
            DWORD hash = hashFunction(functionName);
            
            if (hash == targetHash) {
                return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
            }
        }
        
        return NULL;
    }
    
    // Usage
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    // Hash of "CreateRemoteThread" pre-computed to 0x9E2A9871
    FARPROC createRemoteThread = getFunctionByHash(kernel32, 0x9E2A9871);
    )" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "String Obfuscation Techniques for AV/EDR Evasion" << std::endl;
    std::cout << "=================================================" << std::endl;
    std::cout << std::endl;
    
    demonstrateXorObfuscation();
    demonstrateCharSplitting();
    demonstrateStackConstruction();
    demonstrateBase64Encoding();
    demonstrateAESEncryption();
    demonstrateAPIHashing();
    
    std::cout << "IMPORTANT NOTES:" << std::endl;
    std::cout << "1. These techniques are for educational purposes only" << std::endl;
    std::cout << "2. Modern EDR solutions can detect many of these techniques" << std::endl;
    std::cout << "3. Combining multiple techniques increases effectiveness" << std::endl;
    std::cout << "4. Always clean up sensitive strings from memory when done" << std::endl;
    
    return 0;
}

