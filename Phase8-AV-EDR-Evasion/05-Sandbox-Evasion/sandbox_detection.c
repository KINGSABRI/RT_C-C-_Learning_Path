/**
* @file sandbox_detection.c
* @brief Demonstrates techniques for detecting sandbox and analysis environments
* 
* This file explores various methods to detect if code is running in a sandbox,
* virtual machine, or analysis environment. These techniques are commonly used
* by malware to evade analysis by security researchers and automated analysis systems.
* 
* WARNING: This code is for educational purposes only. Do not use these techniques
* to bypass security controls without proper authorization.
* 
* Compilation (MSYS2/MinGW):
* gcc -std=c11 sandbox_detection.c -o sandbox_detection.exe
* 
* Red Team Applications:
* - Evading automated malware analysis
* - Testing the effectiveness of sandbox environments
* - Understanding how malware detects analysis environments
* - Improving red team tools to avoid detection
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <math.h>

// Function prototypes
void demonstrate_vm_detection();
void demonstrate_sandbox_artifacts();
void demonstrate_timing_detection();
void demonstrate_hardware_detection();
void demonstrate_user_interaction_detection();
BOOL check_vm_mac_address();
BOOL check_vm_registry_artifacts();
BOOL check_vm_processes();
BOOL check_vm_files();
BOOL check_vm_devices();
BOOL check_sandbox_username();
BOOL check_sandbox_hostname();
BOOL check_sandbox_memory();
BOOL check_sandbox_disk_size();
BOOL check_timing_discrepancy();
BOOL check_cpu_features();
BOOL check_mouse_movement();
BOOL check_window_size();

/**
* @brief Main function that demonstrates different sandbox detection techniques
*/
int main() {
    printf("=== Sandbox Detection Techniques Demonstration ===\n");
    printf("\n");
    
    // Demonstrate VM detection
    printf("1. Virtual Machine Detection:\n");
    demonstrate_vm_detection();
    printf("\n");
    
    // Demonstrate sandbox artifacts
    printf("2. Sandbox Artifacts Detection:\n");
    demonstrate_sandbox_artifacts();
    printf("\n");
    
    // Demonstrate timing detection
    printf("3. Timing-Based Detection:\n");
    demonstrate_timing_detection();
    printf("\n");
    
    // Demonstrate hardware detection
    printf("4. Hardware-Based Detection:\n");
    demonstrate_hardware_detection();
    printf("\n");
    
    // Demonstrate user interaction detection
    printf("5. User Interaction Detection:\n");
    demonstrate_user_interaction_detection();
    
    return 0;
}

/**
* @brief Demonstrates techniques for detecting virtual machines
*/
void demonstrate_vm_detection() {
    printf("Virtual machine detection techniques look for artifacts of virtualization:\n");
    printf("- VM-specific hardware identifiers\n");
    printf("- VM-specific processes and services\n");
    printf("- VM-specific registry keys and files\n");
    printf("- VM-specific device drivers\n");
    printf("\n");
    
    // Check VM MAC address
    printf("Checking VM MAC address: ");
    if (check_vm_mac_address()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    // Check VM registry artifacts
    printf("Checking VM registry artifacts: ");
    if (check_vm_registry_artifacts()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    // Check VM processes
    printf("Checking VM processes: ");
    if (check_vm_processes()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    // Check VM files
    printf("Checking VM files: ");
    if (check_vm_files()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    // Check VM devices
    printf("Checking VM devices: ");
    if (check_vm_devices()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    printf("\n");
    printf("CPUID-based detection:\n");
    printf("- Using CPUID instruction to detect hypervisor presence\n");
    
    // Check for hypervisor using CPUID
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 1);
    BOOL hypervisor_present = (cpu_info[2] & (1 << 31)) != 0;
    
    printf("Hypervisor present: %s\n", hypervisor_present ? "Yes" : "No");
    
    if (hypervisor_present) {
        // Get hypervisor vendor ID
        char vendor_id[13] = {0};
        __cpuid(cpu_info, 0x40000000);
        memcpy(vendor_id, &cpu_info[1], 4);
        memcpy(vendor_id + 4, &cpu_info[2], 4);
        memcpy(vendor_id + 8, &cpu_info[3], 4);
        vendor_id[12] = '\0';
        
        printf("Hypervisor vendor ID: %s\n", vendor_id);
    }
}

/**
* @brief Checks for VM-specific MAC addresses
* 
* @return BOOL TRUE if a VM MAC address is detected, FALSE otherwise
*/
BOOL check_vm_mac_address() {
    // This is a simplified implementation
    // In a real scenario, you would enumerate network adapters and check their MAC addresses
    
    // Common VM MAC address prefixes
    const char* vm_mac_prefixes[] = {
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "00:16:3E", // Xen
        "00:1C:42", // Parallels
        "00:03:FF", // Microsoft Hyper-V
        "00:0F:4B", // Virtual Iron
        "00:1C:42"  // Parallels
    };
    
    // In a real implementation, you would get the actual MAC address
    // For demonstration purposes, we'll just return FALSE
    return FALSE;
}

/**
* @brief Checks for VM-specific registry artifacts
* 
* @return BOOL TRUE if VM registry artifacts are detected, FALSE otherwise
*/
BOOL check_vm_registry_artifacts() {
    // Registry keys commonly found in VMs
    const char* vm_registry_keys[] = {
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier",
        "HARDWARE\\Description\\System\\SystemBiosVersion",
        "HARDWARE\\Description\\System\\VideoBiosVersion",
        "HARDWARE\\Description\\System\\SystemManufacturer",
        "HARDWARE\\Description\\System\\SystemProductName",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SYSTEM\\ControlSet001\\Services\\VBoxSF",
        "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
    };
    
    // Check for VM registry keys
    for (int i = 0; i < sizeof(vm_registry_keys) / sizeof(vm_registry_keys[0]); i++) {
        const char* key_path = vm_registry_keys[i];
        char hive[20] = {0};
        char key[256] = {0};
        
        // Extract hive and key
        const char* separator = strchr(key_path, '\\');
        if (separator) {
            size_t hive_len = separator - key_path;
            strncpy(hive, key_path, hive_len);
            hive[hive_len] = '\0';
            strcpy(key, separator + 1);
        }
        
        HKEY hKey = NULL;
        HKEY root_key = HKEY_LOCAL_MACHINE; // Default to HKLM
        
        if (strcmp(hive, "SOFTWARE") == 0) {
            root_key = HKEY_LOCAL_MACHINE;
        } else if (strcmp(hive, "HARDWARE") == 0) {
            root_key = HKEY_LOCAL_MACHINE;
        } else if (strcmp(hive, "SYSTEM") == 0) {
            root_key = HKEY_LOCAL_MACHINE;
        }
        
        if (RegOpenKeyExA(root_key, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return TRUE; // VM registry key found
        }
    }
    
    return FALSE;
}

/**
* @brief Checks for VM-specific processes
* 
* @return BOOL TRUE if VM processes are detected, FALSE otherwise
*/
BOOL check_vm_processes() {
    // Process names commonly found in VMs
    const char* vm_processes[] = {
        "vmtoolsd.exe",     // VMware Tools
        "vmwaretray.exe",   // VMware Tools
        "vmwareuser.exe",   // VMware Tools
        "VBoxService.exe",  // VirtualBox
        "VBoxTray.exe",     // VirtualBox
        "xenservice.exe",   // Xen
        "prl_tools.exe",    // Parallels
        "prl_cc.exe",       // Parallels
        "vmusrvc.exe",      // Microsoft Virtual PC
        "vmsrvc.exe"        // Microsoft Virtual PC
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &process_entry)) {
        do {
            char process_name[MAX_PATH];
            strcpy(process_name, process_entry.szExeFile);
            
            // Convert to lowercase for case-insensitive comparison
            for (int i = 0; process_name[i]; i++) {
                process_name[i] = tolower(process_name[i]);
            }
            
            for (int i = 0; i < sizeof(vm_processes) / sizeof(vm_processes[0]); i++) {
                char lower_vm_process[MAX_PATH];
                strcpy(lower_vm_process, vm_processes[i]);
                
                // Convert to lowercase for case-insensitive comparison
                for (int j = 0; lower_vm_process[j]; j++) {
                    lower_vm_process[j] = tolower(lower_vm_process[j]);
                }
                
                if (strcmp(process_name, lower_vm_process) == 0) {
                    CloseHandle(snapshot);
                    return TRUE; // VM process found
                }
            }
        } while (Process32Next(snapshot, &process_entry));
    }
    
    CloseHandle(snapshot);
    return FALSE;
}

/**
* @brief Checks for VM-specific files
* 
* @return BOOL TRUE if VM files are detected, FALSE otherwise
*/
BOOL check_vm_files() {
    // File paths commonly found in VMs
    const char* vm_files[] = {
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",     // VMware
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",    // VMware
        "C:\\Windows\\System32\\drivers\\vmrawdsk.sys",   // VMware
        "C:\\Windows\\System32\\drivers\\vmusbmouse.sys", // VMware
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",  // VirtualBox
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",  // VirtualBox
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",     // VirtualBox
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",  // VirtualBox
        "C:\\Windows\\System32\\vboxdisp.dll",            // VirtualBox
        "C:\\Windows\\System32\\vboxhook.dll",            // VirtualBox
        "C:\\Windows\\System32\\xennet.sys",              // Xen
        "C:\\Windows\\System32\\xenvbd.sys",              // Xen
        "C:\\Windows\\System32\\xenfilt.sys",             // Xen
        "C:\\Windows\\System32\\xennet6.sys",             // Xen
        "C:\\Program Files\\VMware\\VMware Tools",        // VMware Tools
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions" // VirtualBox Guest Additions
    };
    
    // Check for VM files
    for (int i = 0; i < sizeof(vm_files) / sizeof(vm_files[0]); i++) {
        if (GetFileAttributesA(vm_files[i]) != INVALID_FILE_ATTRIBUTES) {
            return TRUE; // VM file found
        }
    }
    
    return FALSE;
}

/**
* @brief Checks for VM-specific devices
* 
* @return BOOL TRUE if VM devices are detected, FALSE otherwise
*/
BOOL check_vm_devices() {
    // Device names commonly found in VMs
    const char* vm_devices[] = {
        "\\\\.\\HGFS",           // VMware Host-Guest File System
        "\\\\.\\vmci",           // VMware VMCI
        "\\\\.\\VBoxGuest",      // VirtualBox Guest Driver
        "\\\\.\\VBoxMiniRdrDN",  // VirtualBox Shared Folders
        "\\\\.\\pipe\\VBoxTray", // VirtualBox Guest Additions
        "\\\\.\\VBoxMouse",      // VirtualBox Mouse Driver
        "\\\\.\\VBoxVideo"       // VirtualBox Video Driver
    };
    
    // Check for VM devices
    for (int i = 0; i < sizeof(vm_devices) / sizeof(vm_devices[0]); i++) {
        HANDLE device = CreateFileA(
            vm_devices[i],
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        
        if (device != INVALID_HANDLE_VALUE) {
            CloseHandle(device);
            return TRUE; // VM device found
        }
    }
    
    return FALSE;
}

/**
* @brief Demonstrates techniques for detecting sandbox artifacts
*/
void demonstrate_sandbox_artifacts() {
    printf("Sandbox artifact detection looks for signs of analysis environments:\n");
    printf("- Sandbox-specific usernames and hostnames\n");
    printf("- Limited system resources (memory, disk space)\n");
    printf("- Sandbox-specific registry keys and files\n");
    printf("- Lack of user data and history\n");
    printf("\n");
    
    // Check sandbox username
    printf("Checking sandbox username: ");
    if (check_sandbox_username()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    // Check sandbox hostname
    printf("Checking sandbox hostname: ");
    if (check_sandbox_hostname()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    // Check sandbox memory
    printf("Checking sandbox memory: ");
    if (check_sandbox_memory()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    // Check sandbox disk size
    printf("Checking sandbox disk size: ");
    if (check_sandbox_disk_size()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    printf("\n");
    printf("Other sandbox artifacts to check:\n");
    printf("- Recently installed applications (limited in sandboxes)\n");
    printf("- Browser history and cookies (limited in sandboxes)\n");
    printf("- User documents and files (limited in sandboxes)\n");
    printf("- Installed fonts (limited in sandboxes)\n");
    printf("- Presence of analysis tools (debuggers, monitoring tools)\n");
}

/**
* @brief Checks for sandbox-specific usernames
* 
* @return BOOL TRUE if a sandbox username is detected, FALSE otherwise
*/
BOOL check_sandbox_username() {
    // Usernames commonly found in sandboxes
    const char* sandbox_usernames[] = {
        "sandbox",
        "malware",
        "maltest",
        "virus",
        "sample",
        "test",
        "user",
        "admin",
        "administrator",
        "cuckoo",
        "analysis",
        "analyzer",
        "vmware",
        "vbox"
    };
    
    char username[256] = {0};
    DWORD username_len = sizeof(username);
    
    if (GetUserNameA(username, &username_len)) {
        // Convert to lowercase for case-insensitive comparison
        for (int i = 0; username[i]; i++) {
            username[i] = tolower(username[i]);
        }
        
        for (int i = 0; i < sizeof(sandbox_usernames) / sizeof(sandbox_usernames[0]); i++) {
            if (strcmp(username, sandbox_usernames[i]) == 0) {
                return TRUE; // Sandbox username found
            }
        }
    }
    
    return FALSE;
}

/**
* @brief Checks for sandbox-specific hostnames
* 
* @return BOOL TRUE if a sandbox hostname is detected, FALSE otherwise
*/
BOOL check_sandbox_hostname() {
    // Hostnames commonly found in sandboxes
    const char* sandbox_hostnames[] = {
        "sandbox",
        "malware",
        "maltest",
        "virus",
        "sample",
        "test",
        "cuckoo",
        "analysis",
        "analyzer",
        "vmware",
        "vbox",
        "virtualbox",
        "virtual",
        "vm",
        "pc",
        "desktop"
    };
    
    char hostname[256] = {0};
    DWORD hostname_len = sizeof(hostname);
    
    if (GetComputerNameA(hostname, &hostname_len)) {
        // Convert to lowercase for case-insensitive comparison
        for (int i = 0; hostname[i]; i++) {
            hostname[i] = tolower(hostname[i]);
        }
        
        for (int i = 0; i < sizeof(sandbox_hostnames) / sizeof(sandbox_hostnames[0]); i++) {
            if (strstr(hostname, sandbox_hostnames[i]) != NULL) {
                return TRUE; // Sandbox hostname found
            }
        }
    }
    
    return FALSE;
}

/**
* @brief Checks for limited memory resources typical of sandboxes
* 
* @return BOOL TRUE if limited memory is detected, FALSE otherwise
*/
BOOL check_sandbox_memory() {
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);
    
    if (GlobalMemoryStatusEx(&memory_status)) {
        // Check if total physical memory is less than 4 GB
        // Many sandboxes allocate limited memory
        if (memory_status.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
            return TRUE; // Limited memory detected
        }
    }
    
    return FALSE;
}

/**
* @brief Checks for limited disk space typical of sandboxes
* 
* @return BOOL TRUE if limited disk space is detected, FALSE otherwise
*/
BOOL check_sandbox_disk_size() {
    ULARGE_INTEGER free_bytes_available, total_bytes, total_free_bytes;
    
    if (GetDiskFreeSpaceExA("C:\\", &free_bytes_available, &total_bytes, &total_free_bytes)) {
        // Check if total disk space is less than 100 GB
        // Many sandboxes have limited disk space
        if (total_bytes.QuadPart < 100ULL * 1024 * 1024 * 1024) {
            return TRUE; // Limited disk space detected
        }
    }
    
    return FALSE;
}

/**
* @brief Demonstrates timing-based detection techniques
*/
void demonstrate_timing_detection() {
    printf("Timing-based detection exploits differences in execution speed:\n");
    printf("- Sandboxes often run slower than real systems\n");
    printf("- Time acceleration in sandboxes can be detected\n");
    printf("- Sleep skipping in sandboxes can be detected\n");
    printf("- CPU instruction timing differences\n");
    printf("\n");
    
    // Check timing discrepancy
    printf("Checking timing discrepancy: ");
    if (check_timing_discrepancy()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    printf("\n");
    printf("Sleep-based detection:\n");
    printf("- Many sandboxes skip or accelerate sleep calls\n");
    printf("- Comparing expected vs. actual sleep time can detect this\n");
    
    // Measure sleep accuracy
    DWORD sleep_time = 2000; // 2 seconds
    DWORD start_time = GetTickCount();
    
    printf("Sleeping for %lu milliseconds...\n", sleep_time);
    Sleep(sleep_time);
    
    DWORD end_time = GetTickCount();
    DWORD elapsed_time = end_time - start_time;
    
    printf("Actual sleep time: %lu milliseconds\n", elapsed_time);
    
    // Check if sleep time is significantly different from expected
    if (abs((int)(elapsed_time - sleep_time)) > sleep_time / 10) {
        printf("Sleep skipping detected (possible sandbox)\n");
    } else {
        printf("Normal sleep behavior (likely not a sandbox)\n");
    }
}

/**
* @brief Checks for timing discrepancies that might indicate a sandbox
* 
* @return BOOL TRUE if timing discrepancies are detected, FALSE otherwise
*/
BOOL check_timing_discrepancy() {
    // Measure the time it takes to perform a CPU-intensive operation
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    // Perform a CPU-intensive operation
    volatile double result = 0;
    for (int i = 0; i < 1000000; i++) {
        result += sqrt((double)i);
    }
    
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    
    // Check if the operation took significantly longer than expected
    // This threshold would need to be calibrated for different systems
    if (elapsed_ms > 500) {
        return TRUE; // Timing discrepancy detected
    }
    
    return FALSE;
}

/**
* @brief Demonstrates hardware-based detection techniques
*/
void demonstrate_hardware_detection() {
    printf("Hardware-based detection looks for virtualized or emulated hardware:\n");
    printf("- CPU features and behavior\n");
    printf("- Hardware device characteristics\n");
    printf("- BIOS and firmware information\n");
    printf("- Hardware performance characteristics\n");
    printf("\n");
    
    // Check CPU features
    printf("Checking CPU features: ");
    if (check_cpu_features()) {
        printf("Sandbox detected\n");
    } else {
        printf("No sandbox detected\n");
    }
    
    printf("\n");
    printf("CPU information:\n");
    
    // Get CPU vendor string
    char cpu_vendor[13] = {0};
    int cpu_info[4] = {0};
    
    __cpuid(cpu_info, 0);
    memcpy(cpu_vendor, &cpu_info[1], 4);
    memcpy(cpu_vendor + 4, &cpu_info[3], 4);
    memcpy(cpu_vendor + 8, &cpu_info[2], 4);
    cpu_vendor[12] = '\0';
    
    printf("CPU Vendor: %s\n", cpu_vendor);
    
    // Get CPU brand string
    char cpu_brand[49] = {0};
    __cpuid(cpu_info, 0x80000000);
    unsigned int max_extended_id = cpu_info[0];
    
    if (max_extended_id >= 0x80000004) {
        __cpuid(cpu_info, 0x80000002);
        memcpy(cpu_brand, cpu_info, 16);
        
        __cpuid(cpu_info, 0x80000003);
        memcpy(cpu_brand + 16, cpu_info, 16);
        
        __cpuid(cpu_info, 0x80000004);
        memcpy(cpu_brand + 32, cpu_info, 16);
        
        printf("CPU Brand: %s\n", cpu_brand);
    }
    
    // Get CPU core count
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    
    printf("CPU Cores: %lu\n", system_info.dwNumberOfProcessors);
    
    // Check if the number of cores is suspiciously low
    if (system_info.dwNumberOfProcessors < 2) {
        printf("Low core count detected (possible sandbox)\n");
    }
}

/**
* @brief Checks for CPU features that might indicate a sandbox
* 
* @return BOOL TRUE if suspicious CPU features are detected, FALSE otherwise
*/
BOOL check_cpu_features() {
    // Check for CPU features that might indicate a sandbox
    int cpu_info[4] = {0};
    
    // Check for hardware virtualization support
    __cpuid(cpu_info, 1);
    BOOL vmx_support = (cpu_info[2] & (1 << 5)) != 0; // VMX (Intel VT-x)
    
    // Check for hypervisor presence
    BOOL hypervisor_present = (cpu_info[2] & (1 << 31)) != 0;
    
    // In a real VM, hardware virtualization might be disabled
    // and a hypervisor would be present
    if (!vmx_support && hypervisor_present) {
        return TRUE; // Possible sandbox
    }
    
    return FALSE;
}

/**
* @brief Demonstrates user interaction detection techniques
*/
void demonstrate_user_interaction_detection() {
    printf("User interaction detection looks for signs of human activity:\n");
    printf("- Mouse movement and clicks\n");
    printf("- Keyboard input\n");
    printf("- Window focus and interaction\n");
    printf("- Dialog responses\n");
    printf("\n");
    
    // Check mouse movement
    printf("Checking mouse movement: ");
    if (check_mouse_movement()) {
        printf("Human interaction detected\n");
    } else {
        printf("No human interaction detected (possible sandbox)\n");
    }
    
    // Check window size
    printf("Checking window size: ");
    if (check_window_size()) {
        printf("Normal window size detected\n");
    } else {
        printf("Suspicious window size detected (possible sandbox)\n");
    }
    
    printf("\n");
    printf("Dialog-based detection:\n");
    printf("- Many sandboxes automatically dismiss or click through dialogs\n");
    printf("- Timing of dialog responses can indicate automated behavior\n");
    printf("- For demonstration purposes, we won't show an actual dialog\n");
    
    printf("\n");
    printf("Other user interaction checks:\n");
    printf("- Check for recently used files\n");
    printf("- Check browser history and cookies\n");
    printf("- Check for personalized settings\n");
    printf("- Check for user documents and files\n");
}

/**
* @brief Checks for mouse movement that might indicate human interaction
* 
* @return BOOL TRUE if mouse movement is detected, FALSE otherwise
*/
BOOL check_mouse_movement() {
    // Get initial cursor position
    POINT initial_pos;
    if (!GetCursorPos(&initial_pos)) {
        return FALSE;
    }
    
    printf("Initial cursor position: (%ld, %ld)\n", initial_pos.x, initial_pos.y);
    printf("Waiting for mouse movement...\n");
    
    // Wait for a short time
    Sleep(3000); // 3 seconds
    
    // Get new cursor position
    POINT new_pos;
    if (!GetCursorPos(&new_pos)) {
        return FALSE;
    }
    
    printf("New cursor position: (%ld, %ld)\n", new_pos.x, new_pos.y);
    
    // Check if the cursor has moved
    if (initial_pos.x != new_pos.x || initial_pos.y != new_pos.y) {
        return TRUE; // Mouse movement detected
    }
    
    return FALSE;
}

/**
* @brief Checks for window size that might indicate a sandbox
* 
* @return BOOL TRUE if normal window size is detected, FALSE otherwise
*/
BOOL check_window_size() {
    // Get desktop window size
    RECT desktop_rect;
    if (!GetWindowRect(GetDesktopWindow(), &desktop_rect)) {
        return FALSE;
    }
    
    int desktop_width = desktop_rect.right - desktop_rect.left;
    int desktop_height = desktop_rect.bottom - desktop_rect.top;
    
    printf("Desktop resolution: %dx%d\n", desktop_width, desktop_height);
    
    // Check if the resolution is suspiciously low
    // Many sandboxes use low resolutions
    if (desktop_width < 1024 || desktop_height < 768) {
        return FALSE; // Suspicious resolution
    }
    
    // Check foreground window size
    HWND foreground_window = GetForegroundWindow();
    if (foreground_window) {
        RECT window_rect;
        if (GetWindowRect(foreground_window, &window_rect)) {
            int window_width = window_rect.right - window_rect.left;
            int window_height = window_rect.bottom - window_rect.top;
            
            printf("Foreground window size: %dx%d\n", window_width, window_height);
            
            // Check if the window is suspiciously small
            if (window_width < 400 || window_height < 300) {
                return FALSE; // Suspicious window size
            }
        }
    }
    
    return TRUE;
}

/**
* @brief Demonstrates evasion techniques based on sandbox detection
*/
void demonstrate_evasion_techniques() {
    printf("Once a sandbox is detected, malware might employ evasion techniques:\n");
    printf("- Sleep for extended periods to outlast the sandbox analysis\n");
    printf("- Exit or behave benignly when a sandbox is detected\n");
    printf("- Require specific user interaction before executing malicious code\n");
    printf("- Check for specific environment conditions before executing\n");
    printf("\n");
    
    // Example of conditional execution based on sandbox detection
    BOOL sandbox_detected = check_vm_processes() || check_sandbox_username() || 
                           check_sandbox_memory() || !check_mouse_movement();
    
    if (sandbox_detected) {
        printf("Sandbox detected! In malware, this would trigger evasion behavior:\n");
        printf("- Exit the program\n");
        printf("- Execute benign code only\n");
        printf("- Sleep for a very long time\n");
        printf("- Wait for specific user interaction\n");
    } else {
        printf("No sandbox detected! In malware, this would trigger malicious behavior.\n");
        printf("For educational purposes, we won't demonstrate actual malicious behavior.\n");
    }
}

