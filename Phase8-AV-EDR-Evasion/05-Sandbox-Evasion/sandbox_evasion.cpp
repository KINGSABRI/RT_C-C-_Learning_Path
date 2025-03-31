/**
 * sandbox_evasion.cpp
 * 
 * This module demonstrates various techniques used to detect and evade
 * sandbox environments used by AV/EDR solutions for dynamic analysis.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is for learning about security concepts.
 * Using these techniques against systems without authorization is illegal.
 */

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

/**
 * @brief Explains sandbox environments and why malware tries to detect them
 */
void explainSandboxes() {
    std::cout << "=== Understanding Sandbox Environments ===" << std::endl;
    
    std::cout << "Sandboxes are isolated environments used to safely execute and analyze" << std::endl;
    std::cout << "potentially malicious code. They are used by:" << std::endl;
    std::cout << "- Antivirus/EDR solutions for dynamic analysis" << std::endl;
    std::cout << "- Malware researchers to understand malware behavior" << std::endl;
    std::cout << "- Security products to detect zero-day threats" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Malware often attempts to detect sandbox environments to:" << std::endl;
    std::cout << "1. Avoid analysis by not executing malicious code in sandboxes" << std::endl;
    std::cout << "2. Hide its true behavior from security researchers" << std::endl;
    std::cout << "3. Appear benign during automated analysis" << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Demonstrates techniques to detect virtualization
 */
void demonstrateVirtualizationDetection() {
    std::cout << "=== Virtualization Detection Techniques ===" << std::endl;
    
    std::cout << "Many sandboxes run in virtual machines. Detection techniques include:" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. CPU Information Checks:" << std::endl;
    std::cout << R"(
    bool detectVMviaCPUID() {
        int CPUInfo[4] = {-1  << std::endl;
    std::cout << R"(
    bool detectVMviaCPUID() {
        int CPUInfo[4] = {-1};
        
        // CPUID with EAX=1 gets processor info and feature bits
        __cpuid(CPUInfo, 1);
        
        // Check if the hypervisor bit is set in ECX
        // Bit 31 of ECX is set by hypervisors
        if (CPUInfo[2] & (1 << 31)) {
            return true; // Hypervisor detected
        }
        
        // CPUID with EAX=0 gets vendor ID
        char vendor[13];
        __cpuid(CPUInfo, 0);
        memcpy(vendor, &CPUInfo[1], 4);
        memcpy(vendor + 4, &CPUInfo[3], 4);
        memcpy(vendor + 8, &CPUInfo[2], 4);
        vendor[12] = '\0';
        
        // Check for known hypervisor vendor IDs
        if (strcmp(vendor, "VMwareVMware") == 0 ||
            strcmp(vendor, "Microsoft Hv") == 0 ||
            strcmp(vendor, "VBoxVBoxVBox") == 0) {
            return true;
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "2. VM-specific Registry Keys:" << std::endl;
    std::cout << R"(
    bool checkVMRegistryKeys() {
        HKEY hKey;
        char buffer[1024];
        DWORD bufferSize = sizeof(buffer);
        
        // Check for VMware registry keys
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        // Check for VirtualBox registry keys
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        // Check system BIOS information
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                if (strstr(buffer, "VMware") || strstr(buffer, "innotek GmbH") || strstr(buffer, "QEMU")) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "3. VM-specific Files and Drivers:" << std::endl;
    std::cout << R"(
    bool checkVMDrivers() {
        HANDLE hDriver = CreateFileA("\\\\.\\VBoxMiniRdrDN", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            return true; // VirtualBox driver detected
        }
        
        hDriver = CreateFileA("\\\\.\\vmci", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            return true; // VMware driver detected
        }
        
        // Check for VM-specific files
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\drivers\\vmmouse.sys", &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
            return true; // VMware mouse driver detected
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "4. Hardware Fingerprinting:" << std::endl;
    std::cout << R"(
    bool checkHardwareFingerprint() {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        
        // Check for common VM computer names
        if (strstr(computerName, "SANDBOX") || 
            strstr(computerName, "VIRUS") || 
            strstr(computerName, "MALWARE")) {
            return true;
        }
        
        // Check MAC address prefixes
        IP_ADAPTER_INFO adapterInfo[16];
        DWORD adapterInfoSize = sizeof(adapterInfo);
        GetAdaptersInfo(adapterInfo, &adapterInfoSize);
        
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
            // VMware MAC prefixes: 00:05:69, 00:0C:29, 00:1C:14, 00:50:56
            // VirtualBox MAC prefixes: 08:00:27
            if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x05 && adapter->Address[2] == 0x69) ||
                (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
                (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x1C && adapter->Address[2] == 0x14) ||
                (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x50 && adapter->Address[2] == 0x56) ||
                (adapter->Address[0] == 0x08 && adapter->Address[1] == 0x00 && adapter->Address[2] == 0x27)) {
                return true;
            }
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << std::endl;
}

/**
 * @brief Demonstrates techniques to detect sandbox environments
 */
void demonstrateSandboxDetection() {
    std::cout << "=== Sandbox-Specific Detection Techniques ===" << std::endl;
    
    std::cout << "Beyond virtualization, sandboxes have other characteristics:" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Process and DLL Detection:" << std::endl;
    std::cout << R"(
    bool checkSandboxProcesses() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        
        std::vector<std::string> sandboxProcesses = {
            "vmsrvc.exe", "vmusrvc.exe", "vboxtray.exe", "vmtoolsd.exe",
            "df5serv.exe", "sandbox.exe", "sboxie.exe", "sandboxiedcomlaunch.exe",
            "procmon.exe", "wireshark.exe", "fiddler.exe", "dumpcap.exe"
        };
        
        if (Process32First(snapshot, &processEntry)) {
            do {
                for (const auto& process : sandboxProcesses) {
                    if (_stricmp(processEntry.szExeFile, process.c_str()) == 0) {
                        CloseHandle(snapshot);
                        return true; // Sandbox process detected
                    }
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        
        CloseHandle(snapshot);
        
        // Check for analysis DLLs loaded in the current process
        HMODULE modules[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char moduleName[MAX_PATH];
                if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], moduleName, sizeof(moduleName))) {
                    if (strstr(moduleName, "SbieDll.dll") || // Sandboxie
                        strstr(moduleName, "api_log.dll") || // Various sandboxes
                        strstr(moduleName, "dir_watch.dll")) { // Various sandboxes
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "2. User Interaction Detection:" << std::endl;
    std::cout << R"(
    bool detectUserInteraction() {
        // Check mouse movement
        POINT initialPos, currentPos;
        GetCursorPos(&initialPos);
        
        // Sleep for a while
        Sleep(5000);
        
        GetCursorPos(&currentPos);
        
        // If mouse hasn't moved, might be a sandbox
        if (initialPos.x == currentPos.x && initialPos.y == currentPos.y) {
            // Further verification needed - this is just one indicator
            return true;
        }
        
        // Check for dialog box interaction
        // In a real sandbox evasion scenario, this would be more sophisticated
        // and would avoid actually showing a dialog to the user
        /*
        int result = MessageBoxA(NULL, "This is a test", "Test", MB_YESNO);
        if (result == IDYES) {
            // User interaction detected, likely not a sandbox
            return false;
        }
        */
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "3. Time-based Detection:" << std::endl;
    std::cout << R"(
    bool detectTimingAnomalies() {
        // Many sandboxes accelerate time to analyze faster
        // or have timing anomalies due to virtualization
        
        // Method 1: Check for time acceleration
        auto start = std::chrono::high_resolution_clock::now();
        
        // Perform a CPU-intensive operation
        volatile int counter = 0;
        for (int i = 0; i < 10000000; i++) {
            counter++;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        // If the operation took significantly less time than expected,
        // time might be accelerated
        if (duration < 50) { // Threshold needs calibration
            return true;
        }
        
        // Method 2: Sleep timing accuracy
        start = std::chrono::high_resolution_clock::now();
        Sleep(1000); // Sleep for 1 second
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        // Check if the sleep duration is significantly different from expected
        if (duration < 900 || duration > 1100) {
            return true;
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "4. Environment Checks:" << std::endl;
    std::cout << R"(
    bool checkEnvironment() {
        // Check system uptime
        DWORD tickCount = GetTickCount();
        if (tickCount < 5 * 60 * 1000) { // Less than 5 minutes
            // Recently booted system, common for sandboxes
            return true;
        }
        
        // Check number of processors
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) {
            // Many sandboxes use single CPU configuration
            return true;
        }
        
        // Check system memory
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) { // Less than 2GB
            // Low memory systems are often sandboxes
            return true;
        }
        
        // Check for minimal disk space
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
            if (totalNumberOfBytes.QuadPart < 60ULL * 1024 * 1024 * 1024) { // Less than 60GB
                // Small disk size, common for sandboxes
                return true;
            }
        }
        
        // Check for minimal number of installed applications
        // This would require enumerating installed programs
        
        return false;
    }
    )" << std::endl;
    
    std::cout << std::endl;
}

/**
 * @brief Demonstrates techniques to evade sandbox detection
 */
void demonstrateSandboxEvasion() {
    std::cout << "=== Sandbox Evasion Techniques ===" << std::endl;
    
    std::cout << "Once a sandbox is detected, malware can use various techniques to evade analysis:" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Delayed Execution:" << std::endl;
    std::cout << R"(
    void delayedExecution() {
        // Method 1: Simple sleep
        // Many sandboxes have time limits (e.g., 2-5 minutes)
        Sleep(10 * 60 * 1000); // Sleep for 10 minutes
        
        // Method 2: CPU-intensive loop
        auto start = std::chrono::high_resolution_clock::now();
        volatile int counter = 0;
        
        // Loop until 5 minutes have passed
        while (std::chrono::duration_cast<std::chrono::minutes>(
               std::chrono::high_resolution_clock::now() - start).count() < 5) {
            for (int i = 0; i < 10000000; i++) {
                counter++;
            }
        }
        
        // Method 3: Check system idle time
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(LASTINPUTINFO);
        GetLastInputInfo(&lii);
        
        // Wait until system has been idle for at least 30 minutes
        while ((GetTickCount() - lii.dwTime) < 30 * 60 * 1000) {
            Sleep(60000); // Check every minute
            GetLastInputInfo(&lii);
        }
    }
    )" << std::endl;
    
    std::cout << "2. User Interaction Requirements:" << std::endl;
    std::cout << R"(
    bool waitForUserInteraction() {
        // Method 1: Wait for mouse clicks
        int clickCount = 0;
        POINT lastPos = {0, 0};
        
        // Wait for 5 distinct mouse clicks
        while (clickCount < 5) {
            if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                POINT currentPos;
                GetCursorPos(&currentPos);
                
                // Check if this is a new position
                if (currentPos.x != lastPos.x || currentPos.y != lastPos.y) {
                    clickCount++;
                    lastPos = currentPos;
                }
                
                // Wait for button release
                while (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                    Sleep(10);
                }
            }
            Sleep(100);
        }
        
        // Method 2: Wait for keyboard input
        int keyCount = 0;
        
        // Wait for 20 keystrokes
        while (keyCount < 20) {
            for (int key = 0x08; key <= 0xFE; key++) {
                if (GetAsyncKeyState(key) & 0x8000) {
                    keyCount++;
                    
                    // Wait for key release
                    while (GetAsyncKeyState(key) & 0x8000) {
                        Sleep(10);
                    }
                    
                    break;
                }
            }
            Sleep(100);
        }
        
        return true; // User interaction detected
    }
    )" << std::endl;
    
    std::cout << "3. Environment-specific Execution:" << std::endl;
    std::cout << R"(
    bool checkForTargetEnvironment() {
        // Only execute in specific environments
        
        // Method 1: Check for specific files that would exist on a real system
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
        
        if (hFind == INVALID_HANDLE_VALUE) {
            return false; // No user profiles found
        }
        
        int userCount = 0;
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    userCount++;
                }
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
        
        if (userCount < 2) {
            return false; // Too few user profiles
        }
        
        // Method 2: Check for domain membership
        LPWSTR domainName = NULL;
        NETSETUP_JOIN_STATUS joinStatus;
        
        if (NetGetJoinInformation(NULL, &domainName, &joinStatus) == NERR_Success) {
            NetApiBufferFree(domainName);
            
            if (joinStatus == NetSetupDomainName) {
                return true; // Domain-joined machine, likely a corporate environment
            }
        }
        
        // Method 3: Check for specific applications
        if (FindFirstFileA("C:\\Program Files\\Microsoft Office\\*", &findData) != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
            return true; // Microsoft Office installed, likely a real user system
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << "4. Anti-debugging Techniques:" << std::endl;
    std::cout << R"(
    bool detectDebugging() {
        // Method 1: Check IsDebuggerPresent API
        if (IsDebuggerPresent()) {
            return true;
        }
        
        // Method 2: Check PEB.BeingDebugged flag manually
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        if (pPeb->BeingDebugged) {
            return true;
        }
        
        // Method 3: Check for hardware breakpoints
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                return true; // Hardware breakpoints detected
            }
        }
        
        // Method 4: Timing check
        LARGE_INTEGER frequency, start, end;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        
        // RDTSC instruction is often hooked by debuggers
        unsigned long long tsc1 = __rdtsc();
        Sleep(10);
        unsigned long long tsc2 = __rdtsc();
        
        QueryPerformanceCounter(&end);
        
        double elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
        unsigned long long tscDelta = tsc2 - tsc1;
        
        // If the RDTSC delta is significantly different from what we'd expect based on elapsed time,
        // a debugger might be present
        double expectedTscDelta = elapsedTime * 2.4e9; // Assuming 2.4 GHz CPU
        if (tscDelta < expectedTscDelta * 0.5 || tscDelta > expectedTscDelta * 1.5) {
            return true;
        }
        
        return false;
    }
    )" << std::endl;
    
    std::cout << std::endl;
}

/**
 * @brief Discusses countermeasures against sandbox evasion
 */
void discussCountermeasures() {
    std::cout << "=== Countermeasures Against Sandbox Evasion ===" << std::endl;
    
    std::cout << "Modern sandboxes implement various countermeasures:" << std::endl;
    std::cout << std::endl;
    
    std::cout << "1. Virtualization Cloaking:" << std::endl;
    std::cout << "   - Hide virtualization artifacts" << std::endl;
    std::cout << "   - Modify CPUID results" << std::endl;
    std::cout << "   - Hide VM-specific registry keys and files" << std::endl;
    std::cout << std::endl;
    
    std::cout << "2. Time Manipulation:" << std::endl;
    std::cout << "   - Accelerate sleep calls" << std::endl;
    std::cout << "   - Fake system uptime" << std::endl;
    std::cout << "   - Simulate realistic timing" << std::endl;
    std::cout << std::endl;
    
    std::cout << "3. Environment Simulation:" << std::endl;
    std::cout << "   - Simulate user activity" << std::endl;
    std::cout << "   - Provide realistic system properties" << std::endl;
    std::cout << "   - Include common applications and files" << std::endl;
    std::cout << std::endl;
    
    std::cout << "4. Anti-evasion Techniques:" << std::endl;
    std::cout << "   - Monitor for evasion attempts" << std::endl;
    std::cout << "   - Force execution of all code paths" << std::endl;
    std::cout << "   - Use bare-metal analysis for high-value targets" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "Sandbox Detection and Evasion Techniques" << std::endl;
    std::cout << "=======================================" << std::endl;
    std::cout << std::endl;
    
    explainSandboxes();
    demonstrateVirtualizationDetection();
    demonstrateSandboxDetection();
    demonstrateSandboxEvasion();
    discussCountermeasures();
    
    std::cout << "IMPORTANT NOTES:" << std::endl;
    std::cout << "1. These techniques are for educational purposes only" << std::endl;
    std::cout << "2. Understanding evasion techniques helps build better detection" << std::endl;
    std::cout << "3. Modern EDR solutions are aware of these techniques" << std::endl;
    std::cout << "4. Always obtain proper authorization before testing security controls" << std::endl;
    
    return 0;
}

