/**
 * @file detection_mechanisms.cpp
 * @brief Demonstrates common AV/EDR detection mechanisms
 * 
 * This file explores the various detection mechanisms used by antivirus (AV) and
 * endpoint detection and response (EDR) solutions. Understanding these mechanisms
 * is crucial for developing effective evasion techniques and for security testing.
 * 
 * WARNING: This code is for educational purposes only. Do not use these techniques
 * to bypass security controls without proper authorization.
 * 
 * Compilation (MSYS2/MinGW):
 * g++ -std=c++17 detection_mechanisms.cpp -o detection_mechanisms.exe
 * 
 * Red Team Applications:
 * - Understanding how security products detect malicious activity
 * - Developing more effective evasion techniques
 * - Testing the effectiveness of security controls
 * - Improving red team operations
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>

// Function prototypes
void demonstrate_signature_based_detection();
void demonstrate_heuristic_detection();
void demonstrate_behavioral_detection();
void demonstrate_memory_scanning();
void demonstrate_hook_detection();
void print_process_list();
void print_loaded_modules();
void print_api_hooks();

/**
 * @brief Main function that demonstrates different AV/EDR detection mechanisms
 */
int main() {
    std::cout << "=== AV/EDR Detection Mechanisms Demonstration ===" << std::endl;
    std::cout << std::endl;
    
    // Demonstrate signature-based detection
    std::cout << "1. Signature-Based Detection:" << std::endl;
    demonstrate_signature_based_detection();
    std::cout << std::endl;
    
    // Demonstrate heuristic detection
    std::cout << "2. Heuristic Detection:" << std::endl;
    demonstrate_heuristic_detection();
    std::cout << std::endl;
    
    // Demonstrate behavioral detection
    std::cout << "3. Behavioral Detection:" << std::endl;
    demonstrate_behavioral_detection();
    std::cout << std::endl;
    
    // Demonstrate memory scanning
    std::cout << "4. Memory Scanning:" << std::endl;
    demonstrate_memory_scanning();
    std::cout << std::endl;
    
    // Demonstrate hook detection
    std::cout << "5. Hook Detection:" << std::endl;
    demonstrate_hook_detection();
    
    return 0;
}

/**
 * @brief Prints a list of running processes
 */
void print_process_list() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &process_entry)) {
        std::cout << "Running processes:" << std::endl;
        std::cout << "PID\tProcess Name" << std::endl;
        std::cout << "---\t------------" << std::endl;
        
        do {
            std::cout << process_entry.th32ProcessID << "\t" << process_entry.szExeFile << std::endl;
        } while (Process32Next(snapshot, &process_entry));
    }
    
    CloseHandle(snapshot);
}

/**
 * @brief Prints a list of loaded modules in the current process
 */
void print_loaded_modules() {
    HANDLE process = GetCurrentProcess();
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(process, modules, sizeof(modules), &needed)) {
        DWORD module_count = needed / sizeof(HMODULE);
        
        std::cout << "Loaded modules in the current process:" << std::endl;
        std::cout << "Base Address\tModule Name" << std::endl;
        std::cout << "------------\t-----------" << std::endl;
        
        for (DWORD i = 0; i < module_count; i++) {
            char module_name[MAX_PATH];
            
            if (GetModuleFileNameExA(process, modules[i], module_name, sizeof(module_name))) {
                std::cout << std::hex << std::setw(10) << std::setfill('0') << (DWORD_PTR)modules[i] << "\t" 
                        << std::dec << std::setfill(' ') << module_name << std::endl;
            }
        }
    }
}

/**
 * @brief Prints a list of API hooks in common DLLs
 */
void print_api_hooks() {
    // This is a simplified example that checks for hooks in a few common APIs
    
    // Get the address of some common APIs
    FARPROC create_file_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileA");
    FARPROC read_file_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "ReadFile");
    FARPROC write_file_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteFile");
    FARPROC create_process_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA");
    
    std::cout << "Checking for API hooks:" << std::endl;
    
    // Check for JMP or CALL instructions at the beginning of the functions
    if (create_file_addr) {
        BYTE* code = (BYTE*)create_file_addr;
        if (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xFF || code[0] == 0xE8) {
            std::cout << "CreateFileA appears to be hooked" << std::endl;
        } else {
            std::cout << "CreateFileA does not appear to be hooked" << std::endl;
        }
    }
    
    if (read_file_addr) {
        BYTE* code = (BYTE*)read_file_addr;
        if (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xFF || code[0] == 0xE8) {
            std::cout << "ReadFile appears to be hooked" << std::endl;
        } else {
            std::cout << "ReadFile does not appear to be hooked" << std::endl;
        }
    }
    
    if (write_file_addr) {
        BYTE* code = (BYTE*)write_file_addr;
        if (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xFF || code[0] == 0xE8) {
            std::cout << "WriteFile appears to be hooked" << std::endl;
        } else {
            std::cout << "WriteFile does not appear to be hooked" << std::endl;
        }
    }
    
    if (create_process_addr) {
        BYTE* code = (BYTE*)create_process_addr;
        if (code[0] == 0xE9 || code[0] == 0xEB || code[0] == 0xFF || code[0] == 0xE8) {
            std::cout << "CreateProcessA appears to be hooked" << std::endl;
        } else {
            std::cout << "CreateProcessA does not appear to be hooked" << std::endl;
        }
    }
}

/**
 * @brief Demonstrates signature-based detection mechanisms
 */
void demonstrate_signature_based_detection() {
    std::cout << "Signature-based detection involves matching patterns in files or memory:" << std::endl;
    std::cout << "- Static signatures: Specific byte sequences or hashes" << std::endl;
    std::cout << "- YARA rules: More complex pattern matching" << std::endl;
    std::cout << "- Fuzzy hashing: Similarity-based detection" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example static signature:" << std::endl;
    std::cout << "Signature for EICAR test file:" << std::endl;
    std::cout << "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example YARA rule:" << std::endl;
    std::cout << "rule Mimikatz_Detection {" << std::endl;
    std::cout << "    strings:" << std::endl;
    std::cout << "        $s1 = \"mimikatz\" nocase" << std::endl;
    std::cout << "        $s2 = \"mimilib\" nocase" << std::endl;
    std::cout << "        $s3 = \"sekurlsa::logonpasswords\" nocase" << std::endl;
    std::cout << "        $s4 = \"kerberos::list\" nocase" << std::endl;
    std::cout << "    condition:" << std::endl;
    std::cout << "        2 of them" << std::endl;
    std::cout << "}" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Signature-based detection strengths:" << std::endl;
    std::cout << "- Fast and efficient" << std::endl;
    std::cout << "- Low false positive rate for known threats" << std::endl;
    std::cout << "- Easy to implement and update" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Signature-based detection weaknesses:" << std::endl;
    std::cout << "- Cannot detect unknown or modified threats" << std::endl;
    std::cout << "- Easily evaded by obfuscation or polymorphism" << std::endl;
    std::cout << "- Requires constant updates" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Common evasion techniques:" << std::endl;
    std::cout << "1. Obfuscation: Modifying the code to hide patterns" << std::endl;
    std::cout << "2. Encryption: Encrypting the payload to hide signatures" << std::endl;
    std::cout << "3. Polymorphism: Changing the code structure while maintaining functionality" << std::endl;
    std::cout << "4. Fragmentation: Splitting the code into smaller, less detectable pieces" << std::endl;
    std::cout << "5. Metamorphism: Completely rewriting the code while maintaining functionality" << std::endl;
}

/**
 * @brief Demonstrates heuristic detection mechanisms
 */
void demonstrate_heuristic_detection() {
    std::cout << "Heuristic detection involves analyzing code for suspicious characteristics:" << std::endl;
    std::cout << "- Static heuristics: Analyzing file structure and content" << std::endl;
    std::cout << "- Dynamic heuristics: Analyzing code behavior during execution" << std::endl;
    std::cout << "- Machine learning: Using AI to identify malicious patterns" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Common heuristic indicators:" << std::endl;
    std::cout << "1. File characteristics:" << std::endl;
    std::cout << "   - Unusual section names or sizes" << std::endl;
    std::cout << "   - High entropy (indicating encryption or packing)" << std::endl;
    std::cout << "   - Suspicious imports or exports" << std::endl;
    std::cout << "   - Unusual compiler artifacts" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. Code characteristics:" << std::endl;
    std::cout << "   - Self-modifying code" << std::endl;
    std::cout << "   - Anti-debugging techniques" << std::endl;
    std::cout << "   - Obfuscated strings or code" << std::endl;
    std::cout << "   - Unusual API call patterns" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Behavioral characteristics:" << std::endl;
    std::cout << "   - Process injection" << std::endl;
    std::cout << "   - Registry modifications" << std::endl;
    std::cout << "   - Network activity" << std::endl;
    std::cout << "   - File system activity" << std::endl;
    std::

