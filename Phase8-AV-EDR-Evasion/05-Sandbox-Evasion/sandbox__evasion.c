/**
* @file string_obfuscation.c
* @brief Demonstrates string obfuscation techniques for evading signature-based detection
* 
* This file explores various methods to obfuscate strings in memory and in compiled
* binaries to evade signature-based detection by antivirus and EDR solutions.
* String obfuscation is a common technique used to hide suspicious strings like
* API names, commands, and URLs.
* 
* WARNING: This code is for educational purposes only. Do not use these techniques
* to bypass security controls without proper authorization.
* 
* Compilation (MSYS2/MinGW):
* gcc -std=c11 string_obfuscation.c -o string_obfuscation.exe
* 
* Red Team Applications:
* - Evading signature-based detection
* - Hiding suspicious strings in malware
* - Bypassing static analysis
* - Understanding how malware hides its functionality
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// Function prototypes
void demonstrate_xor_encoding();
void demonstrate_base64_encoding();
void demonstrate_caesar_cipher();
void demonstrate_stack_strings();
void demonstrate_string_splitting();
void demonstrate_string_encryption();
void demonstrate_api_hashing();
char* xor_encode(const char* input, char key);
char* xor_decode(const char* input, size_t length, char key);
char* base64_encode(const char* input, size_t length);
char* base64_decode(const char* input, size_t* output_length);
char* caesar_cipher(const char* input, int shift);
char* caesar_decipher(const char* input, int shift);
char* construct_stack_string();
char* construct_split_string();
char* decrypt_string(const unsigned char* encrypted, size_t length, const char* key);
DWORD compute_hash(const char* name);

/**
* @brief Main function that demonstrates different string obfuscation techniques
*/
int main() {
    printf("=== String Obfuscation Techniques Demonstration ===\n");
    printf("\n");
    
    // Demonstrate XOR encoding
    printf("1. XOR Encoding:\n");
    demonstrate_xor_encoding();
    printf("\n");
    
    // Demonstrate Base64 encoding
    printf("2. Base64 Encoding:\n");
    demonstrate_base64_encoding();
    printf("\n");
    
    // Demonstrate Caesar cipher
    printf("3. Caesar Cipher:\n");
    demonstrate_caesar_cipher();
    printf("\n");
    
    // Demonstrate stack strings
    printf("4. Stack Strings:\n");
    demonstrate_stack_strings();
    printf("\n");
    
    // Demonstrate string splitting
    printf("5. String Splitting:\n");
    demonstrate_string_splitting();
    printf("\n");
    
    // Demonstrate string encryption
    printf("6. String Encryption:\n");
    demonstrate_string_encryption();
    printf("\n");
    
    // Demonstrate API hashing
    printf("7. API Hashing:\n");
    demonstrate_api_hashing();
    
    return 0;
}

/**
* @brief Demonstrates XOR encoding for string obfuscation
*/
void demonstrate_xor_encoding() {
    printf("XOR encoding is a simple but effective obfuscation technique:\n");
    printf("- Each character is XORed with a key value\n");
    printf("- The same operation is used for encoding and decoding\n");
    printf("- Can use a single byte key or a multi-byte key\n");
    printf("\n");
    
    // Original string
    const char* original = "CreateRemoteThread";
    char key = 0x37; // XOR key
    
    printf("Original string: %s\n", original);
    
    // Encode the string
    char* encoded = xor_encode(original, key);
    
    // Print the encoded string as hex
    printf("XOR encoded (key=0x%02x): ", key);
    for (size_t i = 0; i < strlen(original); i++) {
        printf("%02x ", (unsigned char)encoded[i]);
    }
    printf("\n");
    
    // Decode the string
    char* decoded = xor_decode(encoded, strlen(original), key);
    printf("Decoded string: %s\n", decoded);
    
    // Clean up
    free(encoded);
    free(decoded);
    
    printf("\n");
    printf("Implementation example:\n");
    printf("char key = 0x37;\n");
    printf("char encoded[] = { /* encoded bytes */ };\n");
    printf("char decoded[sizeof(encoded)];\n");
    printf("for (int i = 0; i < sizeof(encoded); i++) {\n");
    printf("    decoded[i] = encoded[i] ^ key;\n");
    printf("}\n");
    
    printf("\n");
    printf("Multi-byte XOR key example:\n");
    printf("char key[] = { 0x37, 0x42, 0x86, 0x91 };\n");
    printf("char encoded[] = { /* encoded bytes */ };\n");
    printf("char decoded[sizeof(encoded)];\n");
    printf("for (int i = 0; i < sizeof(encoded); i++) {\n");
    printf("    decoded[i] = encoded[i] ^ key[i %% sizeof(key)];\n");
    printf("}\n");
}

/**
* @brief XOR encodes a string with a single-byte key
* 
* @param input The string to encode
* @param key The XOR key
* @return char* The encoded string (must be freed by the caller)
*/
char* xor_encode(const char* input, char key) {
    size_t length = strlen(input);
    char* result = (char*)malloc(length + 1);
    
    if (result) {
        for (size_t i = 0; i < length; i++) {
            result[i] = input[i] ^ key;
        }
        result[length] = '\0';
    }
    
    return result;
}

/**
* @brief XOR decodes a string with a single-byte key
* 
* @param input The string to decode
* @param length The length of the input
* @param key The XOR key
* @return char* The decoded string (must be freed by the caller)
*/
char* xor_decode(const char* input, size_t length, char key) {
    // XOR is symmetric, so encoding and decoding are the same operation
    char* result = (char*)malloc(length + 1);
    
    if (result) {
        for (size_t i = 0; i < length; i++) {
            result[i] = input[i] ^ key;
        }
        result[length] = '\0';
    }
    
    return result;
}

/**
* @brief Demonstrates Base64 encoding for string obfuscation
*/
void demonstrate_base64_encoding() {
    printf("Base64 encoding converts binary data to ASCII text:\n");
    printf("- Uses a set of 64 characters (A-Z, a-z, 0-9, +, /)\n");
    printf("- Commonly used for transmitting binary data in text-based formats\n");
    printf("- Not secure by itself, but can be combined with other techniques\n");
    printf("\n");
    
    // Original string
    const char* original = "VirtualAllocEx";
    
    printf("Original string: %s\n", original);
    
    // Encode the string
    char* encoded = base64_encode(original, strlen(original));
    printf("Base64 encoded: %s\n", encoded);
    
    // Decode the string
    size_t decoded_length;
    char* decoded = base64_decode(encoded, &decoded_length);
    printf("Decoded string: %s\n", decoded);
    
    // Clean up
    free(encoded);
    free(decoded);
    
    printf("\n");
    printf("Implementation example:\n");
    printf("// Base64 encoded string\n");
    printf("const char* encoded = \"VmlydHVhbEFsbG9jRXg=\";\n");
    printf("// Decode at runtime\n");
    printf("size_t decoded_length;\n");
    printf("char* decoded = base64_decode(encoded, &decoded_length);\n");
    printf("// Use the decoded string\n");
    printf("LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);\n");
    printf("pVirtualAllocEx = (LPVOID (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))\n");
    printf("    GetProcAddress(GetModuleHandle(\"kernel32.dll\"), decoded);\n");
}

/**
* @brief Base64 encodes a string
* 
* @param input The string to encode
* @param length The length of the input
* @return char* The Base64 encoded string (must be freed by the caller)
*/
char* base64_encode(const char* input, size_t length) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    size_t output_length = 4 * ((length + 2) / 3);
    char* result = (char*)malloc(output_length + 1);
    
    if (result) {
        size_t i, j;
        for (i = 0, j = 0; i < length; i += 3, j += 4) {
            unsigned char a = i < length ? input[i] : 0;
            unsigned char b = i + 1 < length ? input[i + 1] : 0;
            unsigned char c = i + 2 < length ? input[i + 2] : 0;
            
            unsigned char triple[3] = {a, b, c};
            
            result[j] = base64_chars[triple[0] >> 2];
            result[j + 1] = base64_chars[((triple[0] & 0x03) << 4) | (triple[1] >> 4)];
            result[j + 2] = base64_chars[((triple[1] & 0x0f) << 2) | (triple[2] >> 6)];
            result[j + 3] = base64_chars[triple[2] & 0x3f];
        }
        
        // Add padding
        if (length % 3 == 1) {
            result[output_length - 2] = '=';
            result[output_length - 1] = '=';
        } else if (length % 3 == 2) {
            result[output_length - 1] = '=';
        }
        
        result[output_length] = '\0';
    }
    
    return result;
}

/**
* @brief Base64 decodes a string
* 
* @param input The Base64 encoded string
* @param output_length Output parameter that receives the length of the decoded data
* @return char* The decoded string (must be freed by the caller)
*/
char* base64_decode(const char* input, size_t* output_length) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    size_t input_length = strlen(input);
    size_t padding = 0;
    
    // Count padding characters
    if (input_length > 0 && input[input_length - 1] == '=') padding++;
    if (input_length > 1 && input[input_length - 2] == '=') padding++;
    
    // Calculate output length
    *output_length = 3 * (input_length / 4) - padding;
    char* result = (char*)malloc(*output_length + 1);
    
    if (result) {
        size_t i, j;
        for (i = 0, j = 0; i < input_length; i += 4, j += 3) {
            char a = strchr(base64_chars, input[i]) - base64_chars;
            char b = strchr(base64_chars, input[i + 1]) - base64_chars;
            char c = input[i + 2] == '=' ? 0 : strchr(base64_chars, input[i + 2]) - base64_chars;
            char d = input[i + 3] == '=' ? 0 : strchr(base64_chars, input[i + 3]) - base64_chars;
            
            result[j] = (a << 2) | (b >> 4);
            if (j + 1 < *output_length) result[j + 1] = (b << 4) | (c >> 2);
            if (j + 2 < *output_length) result[j + 2] = (c << 6) | d;
        }
        
        result[*output_length] = '\0';
    }
    
    return result;
}

/**
* @brief Demonstrates Caesar cipher for string obfuscation
*/
void demonstrate_caesar_cipher() {
    printf("Caesar cipher is a simple substitution cipher:\n");
    printf("- Each character is shifted by a fixed amount\n");
    printf("- Easy to implement but also easy to break\n");
    printf("- Can be combined with other techniques for better obfuscation\n");
    printf("\n");
    
    // Original string
    const char* original = "WriteProcessMemory";
    int shift = 7; // Shift amount
    
    printf("Original string: %s\n", original);
    
    // Encode the string
    char* encoded = caesar_cipher(original, shift);
    printf("Caesar cipher (shift=%d): %s\n", shift, encoded);
    
    // Decode the string
    char* decoded = caesar_decipher(encoded, shift);
    printf("Decoded string: %s\n", decoded);
    
    // Clean up
    free(encoded);
    free(decoded);
    
    printf("\n");
    printf("Implementation example:\n");
    printf("int shift = 7;\n");
    printf("char encoded[] = \"^yp{lWyvjlzzTltvyf\";\n");
    printf("char decoded[sizeof(encoded)];\n");
    printf("for (int i = 0; i < sizeof(encoded) - 1; i++) {\n");
    printf("    decoded[i] = encoded[i] - shift;\n");
    printf("}\n");
    printf("decoded[sizeof(encoded) - 1] = '\\0';\n");
}

/**
* @brief Applies a Caesar cipher to a string
* 
* @param input The string to encode
* @param shift The shift amount
* @return char* The encoded string (must be freed by the caller)
*/
char* caesar_cipher(const char* input, int shift) {
    size_t length = strlen(input);
    char* result = (char*)malloc(length + 1);
    
    if (result) {
        for (size_t i = 0; i < length; i++) {
            result[i] = input[i] + shift;
        }
        result[length] = '\0';
    }
    
    return result;
}

/**
* @brief Decodes a Caesar cipher
* 
* @param input The encoded string
* @param shift The shift amount
* @return char* The decoded string (must be freed by the caller)
*/
char* caesar_decipher(const char* input, int shift) {
    size_t length = strlen(input);
    char* result = (char*)malloc(length + 1);
    
    if (result) {
        for (size_t i = 0; i < length; i++) {
            result[i] = input[i] - shift;
        }
        result[length] = '\0';
    }
    
    return result;
}

/**
* @brief Demonstrates stack strings for string obfuscation
*/
void demonstrate_stack_strings() {
    printf("Stack strings are constructed at runtime to avoid static detection:\n");
    printf("- Characters are stored separately and assembled at runtime\n");
    printf("- Prevents static analysis from finding complete strings\n");
    printf("- Can be implemented in various ways\n");
    printf("\n");
    
    // Construct a stack string
    char* constructed = construct_stack_string();
    printf("Constructed stack string: %s\n", constructed);
    
    // Clean up
    free(constructed);
    
    printf("\n");
    printf("Implementation example:\n");
    printf("char stack_string[17];\n");
    printf("stack_string[0] = 'C';\n");
    printf("stack_string[1] = 'r';\n");
    printf("stack_string[2] = 'e';\n");
    printf("stack_string[3] = 'a';\n");
    printf("stack_string[4] = 't';\n");
    printf("stack_string[5] = 'e';\n");
    printf("stack_string[6] = 'P';\n");
    printf("stack_string[7] = 'r';\n");
    printf("stack_string[8] = 'o';\n");
    printf("stack_string[9] = 'c';\n");
    printf("stack_string[10] = 'e';\n");
    printf("stack_string[11] = 's';\n");
    printf("stack_string[12] = 's';\n");
    printf("stack_string[13] = 'A';\n");
    printf("stack_string[14] = 'P';\n");
    printf("stack_string[15] = 'I';\n");
    printf("stack_string[16] = '\\0';\n");
    
    printf("\n");
    printf("Alternative implementation using array:\n");
    printf("char chars[] = {'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 'P', 'I', '\\0'};\n");
    printf("char* api_name = chars;\n");
}

/**
* @brief Constructs a string at runtime (stack string)
* 
* @return char* The constructed string (must be freed by the caller)
*/
char* construct_stack_string() {
    char* stack_string = (char*)malloc(17);
    
    if (stack_string) {
        stack_string[0] = 'C';
        stack_string[1] = 'r';
        stack_string[2] = 'e';
        stack_string[3] = 'a';
        stack_string[4] = 't';
        stack_string[5] = 'e';
        stack_string[6] = 'P';
        stack_string[7] = 'r';
        stack_string[8] = 'o';
        stack_string[9] = 'c';
        stack_string[10] = 'e';
        stack_string[11] = 's';
        stack_string[12] = 's';
        stack_string[13] = 'A';
        stack_string[14] = 'P';
        stack_string[15] = 'I';
        stack_string[16] = '\0';
    }
    
    return stack_string;
}

/**
* @brief Demonstrates string splitting for obfuscation
*/
void demonstrate_string_splitting() {
    printf("String splitting breaks strings into smaller parts:\n");
    printf("- Strings are split into multiple parts and concatenated at runtime\n");
    printf("- Prevents static analysis from finding complete strings\n");
    printf("- Can be combined with other techniques\n");
    printf("\n");
    
    // Construct a split string
    char* constructed = construct_split_string();
    printf("Constructed split string: %s\n", constructed);
    
    // Clean up
    free(constructed);
    
    printf("\n");
    printf("Implementation example:\n");
    printf("char part1[] = \"Load\";\n");
    printf("char part2[] = \"Library\";\n");
    printf("char part3[] = \"A\";\n");
    printf("char full_api[strlen(part1) + strlen(part2) + strlen(part3) + 1];\n");
    printf("strcpy(full_api, part1);\n");
    printf("strcat(full_api, part2);\n");
    printf("strcat(full_api, part3);\n");
}

/**
* @brief Constructs a string by concatenating parts
* 
* @return char* The constructed string (must be freed by the caller)
*/
char* construct_split_string() {
    const char* part1 = "Load";
    const char* part2 = "Library";
    const char* part3 = "A";
    
    size_t total_length = strlen(part1) + strlen(part2) + strlen(part3) + 1;
    char* result = (char*)malloc(total_length);
    
    if (result) {
        strcpy(result, part1);
        strcat(result, part2);
        strcat(result, part3);
    }
    
    return result;
}

/**
* @brief Demonstrates string encryption for obfuscation
*/
void demonstrate_string_encryption() {
    printf("String encryption uses cryptographic algorithms:\n");
    printf("- Strings are encrypted and decrypted at runtime\n");
    printf("- Provides stronger protection than simple encoding\n");
    printf("- Can use various encryption algorithms\n");
    printf("\n");
    
    // Original string
    const char* original = "GetProcAddress";
    const char* key = "SecretKey123";
    
    printf("Original string: %s\n", original);
    
    // Encrypt the string (simplified for demonstration)
    size_t original_length = strlen(original);
    size_t key_length = strlen(key);
    unsigned char* encrypted = (unsigned char*)malloc(original_length);
    
    if (encrypted) {
        for (size_t i = 0; i < original_length; i++) {
            encrypted[i] = original[i] ^ key[i % key_length];
        }
        
        // Print the encrypted string as hex
        printf("Encrypted: ");
        for (size_t i = 0; i < original_length; i++) {
            printf("%02x ", encrypted[i]);
        }
        printf("\n");
        
        // Decrypt the string
        char* decrypted = decrypt_string(encrypted, original_length, key);
        printf("Decrypted string: %s\n", decrypted);
        
        // Clean up
        free(encrypted);
        free(decrypted);
    }
    
    printf("\n");
    printf("Implementation example:\n");
    printf("// Encrypted string (pre-computed)\n");
    printf("unsigned char encrypted[] = { /* encrypted bytes */ };\n");
    printf("char key[] = \"SecretKey123\";\n");
    printf("char decrypted[sizeof(encrypted)];\n");
    printf("for (int i = 0; i < sizeof(encrypted); i++) {\n");
    printf("    decrypted[i] = encrypted[i] ^ key[i %% sizeof(key)];\n");
    printf("}\n");
    printf("decrypted[sizeof(encrypted)] = '\\0';\n");
    
    printf("\n");
    printf("More advanced encryption methods:\n");
    printf("- AES encryption\n");
    printf("- RC4 encryption\n");
    printf("- Blowfish encryption\n");
    printf("- Custom encryption algorithms\n");
}

/**
* @brief Decrypts a string using XOR with a key
* 
* @param encrypted The encrypted data
* @param length The length of the encrypted data
* @param key The encryption key
* @return char* The decrypted string (must be freed by the caller)
*/
char* decrypt_string(const unsigned char* encrypted, size_t length, const char* key) {
    size_t key_length = strlen(key);
    char* result = (char*)malloc(length + 1);
    
    if (result) {
        for (size_t i = 0; i < length; i++) {
            result[i] = encrypted[i] ^ key[i % key_length];
        }
        result[length] = '\0';
    }
    
    return result;
}

/**
* @brief Demonstrates API hashing for obfuscation
*/
void demonstrate_api_hashing() {
    printf("API hashing uses hash values instead of API names:\n");
    printf("- API names are replaced with their hash values\n");
    printf("- Functions are resolved at runtime using the hash values\n");
    printf("- Prevents static analysis from finding API names\n");
    printf("\n");
    
    // API names to hash
    const char* api_names[] = {
        "CreateProcessA",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibraryA",
        "GetProcAddress"
    };
    
    // Compute and print hash values
    printf("API name hashes:\n");
    for (int i = 0; i < sizeof(api_names) / sizeof(api_names[0]); i++) {
        DWORD hash = compute_hash(api_names[i]);
        printf("%s: 0x%08lx\n", api_names[i], hash);
    }
    
    printf("\n");
    printf("Implementation example:\n");
    printf("// Compute hash of API name\n");
    printf("DWORD compute_hash(const char* name) {\n");
    printf("    DWORD hash = 0;\n");
    printf("    while (*name) {\n");
    printf("        hash = ((hash << 5) + hash) + *name++;\n");
    printf("    }\n");
    printf("    return hash;\n");
    printf("}\n");
    printf("\n");
    printf("// Find function by hash\n");
    printf("typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);\n");
    printf("typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);\n");
    printf("\n");
    printf("FARPROC get_function_by_hash(HMODULE module, DWORD hash) {\n");
    printf("    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;\n");
    printf("    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module + dos_header->e_lfanew);\n");
    printf("    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module +\n");
    printf("        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n");
    printf("\n");
    printf("    DWORD* address_of_functions = (DWORD*)((BYTE*)module + export_dir->AddressOfFunctions);\n");
    printf("    DWORD* address_of_names = (DWORD*)((BYTE*)module + export_dir->AddressOfNames);\n");
    printf("    WORD* address_of_name_ordinals = (WORD*)((BYTE*)module + export_dir->AddressOfNameOrdinals);\n");
    printf("\n");
    printf("    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {\n");
    printf("        char* name = (char*)((BYTE*)module + address_of_names[i]);\n");
    printf("        if (compute_hash(name) == hash) {\n");
    printf("            return (FARPROC)((BYTE*)module + address_of_functions[address_of_name_ordinals[i]]);\n");
    printf("        }\n");
    printf("    }\n");
    printf("    return NULL;\n");
    printf("}\n");
}

/**
* @brief Computes a hash value for a string
* 
* @param name The string to hash
* @return DWORD The hash value
*/
DWORD compute_hash(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = ((hash << 5) + hash) + *name++;
    }
    return hash;
}

/**
* @brief Demonstrates combining multiple obfuscation techniques
*/
void demonstrate_combined_techniques() {
    printf("Combining multiple obfuscation techniques provides stronger protection:\n");
    printf("- Encrypt strings with a strong algorithm\n");
    printf("- Use API hashing to resolve functions\n");
    printf("- Implement control flow obfuscation\n");
    printf("- Add anti-debugging checks\n");
    printf("\n");
    
    printf("Example of combined techniques:\n");
    printf("1. Encrypt API names with AES\n");
    printf("2. Decrypt names at runtime\n");
    printf("3. Compute hash of decrypted names\n");
    printf("4. Resolve functions using hashes\n");
    printf("5. Use resolved functions\n");
    
    printf("\n");
    printf("Advanced obfuscation considerations:\n");
    printf("- Implement code virtualization\n");
    printf("- Use polymorphic code generation\n");
    printf("- Add junk code and dead code\n");
    printf("- Implement control flow flattening\n");
    printf("- Use instruction substitution\n");
}

