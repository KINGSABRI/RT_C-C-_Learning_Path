/**
 * detection_methods.cpp
 * 
 * This module demonstrates various detection methods used by AV/EDR solutions
 * and explains how they work.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is for learning about security concepts.
 * Using these techniques against systems without authorization is illegal.
 */

#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

/**
 * @brief Demonstrates signature-based detection
 * 
 * Signature-based detection is one of the oldest and most common methods
 * used by antivirus software. It works by comparing files against a database
 * of known malicious patterns (signatures).
 */
void demonstrateSignatureDetection() {
    std::cout << "=== Signature-Based Detection ===" << std::endl;
    
    // This is a harmless string but resembles patterns that might be flagged
    // Many AVs would flag strings like "CreateRemoteThread" combined with "VirtualAllocEx"
    std::string potentiallyFlaggedCode = R"(
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
        LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(payload), 
                                            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, remoteBuffer, payload, sizeof(payload), NULL);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)remoteBuffer, 
                                           NULL, 0, NULL);
    )";
    
    std::cout << "Example of code that might trigger signature detection:" << std::endl;
    std::cout << potentiallyFlaggedCode << std::endl;
    std::cout << "Why: Contains API combinations commonly used in malware" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates heuristic-based detection
 * 
 * Heuristic-based detection looks for suspicious behaviors or characteristics
 * rather than specific signatures. It can detect previously unknown malware.
 */
void demonstrateHeuristicDetection() {
    std::cout << "=== Heuristic-Based Detection ===" << std::endl;
    
    std::vector<std::string> suspiciousBehaviors = {
        "Modifying the registry autorun keys",
        "Injecting code into other processes",
        "Attempting to disable security software",
        "Encrypting files on the system",
        "Connecting to known malicious IP addresses",
        "Excessive use of obfuscation techniques"
    };
    
    std::cout << "Behaviors that might trigger heuristic detection:" << std::endl;
    for (const auto& behavior : suspiciousBehaviors) {
        std::cout << "- " << behavior << std::endl;
    }
    std::cout << std::endl;
}

/**
 * @brief Demonstrates behavior-based detection
 * 
 * Behavior-based detection monitors the actions of programs in real-time
 * to identify malicious behavior.
 */
void demonstrateBehaviorDetection() {
    std::cout << "=== Behavior-Based Detection ===" << std::endl;
    
    std::cout << "Example of runtime behaviors monitored by EDR:" << std::endl;
    std::cout << "1. Process creation chains" << std::endl;
    std::cout << "2. File system operations" << std::endl;
    std::cout << "3. Registry modifications" << std::endl;
    std::cout << "4. Network connections" << std::endl;
    std::cout << "5. Memory modifications" << std::endl;
    std::cout << "6. API call sequences" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example of a suspicious behavior chain:" << std::endl;
    std::cout << "Word.exe -> cmd.exe -> powershell.exe (with encoded command) -> network connection" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates machine learning-based detection
 * 
 * Modern AV/EDR solutions use machine learning to identify patterns
 * and characteristics of malicious software.
 */
void demonstrateMLDetection() {
    std::cout << "=== Machine Learning-Based Detection ===" << std::endl;
    
    std::cout << "Features analyzed by ML-based detection:" << std::endl;
    std::cout << "- File characteristics (size, entropy, etc.)" << std::endl;
    std::cout << "- API call sequences" << std::endl;
    std::cout << "- Control flow patterns" << std::endl;
    std::cout << "- String characteristics" << std::endl;
    std::cout << "- Header information" << std::endl;
    std::cout << "- Import/export tables" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates memory scanning techniques
 * 
 * EDR solutions often scan process memory to detect malicious code
 * that might not exist on disk.
 */
void demonstrateMemoryScanning() {
    std::cout << "=== Memory Scanning ===" << std::endl;
    
    std::cout << "Memory scanning techniques:" << std::endl;
    std::cout << "1. Scanning for known signatures in process memory" << std::endl;
    std::cout << "2. Detecting shellcode characteristics (high entropy, executable flags)" << std::endl;
    std::cout << "3. Identifying suspicious memory regions (RWX permissions)" << std::endl;
    std::cout << "4. Detecting hooks and patches in memory" << std::endl;
    std::cout << "5. Identifying process injection artifacts" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "Understanding AV/EDR Detection Methods" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;
    
    demonstrateSignatureDetection();
    demonstrateHeuristicDetection();
    demonstrateBehaviorDetection();
    demonstrateMLDetection();
    demonstrateMemoryScanning();
    
    std::cout << "Understanding these detection methods is crucial for:" << std::endl;
    std::cout << "1. Building better security solutions" << std::endl;
    std::cout << "2. Testing the effectiveness of existing solutions" << std::endl;
    std::cout << "3. Understanding the limitations of current technologies" << std::endl;
    
    return 0;
}

