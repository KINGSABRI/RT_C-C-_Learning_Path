#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

// Red Team Focus: Thread management can be used to:
// 1. Execute code in the context of another process
// 2. Implement multi-threaded malware
// 3. Bypass thread-based security controls
// 4. Hide malicious activity

// Thread function prototype
DWORD WINAPI ThreadFunction(LPVOID lpParam);

// Thread parameter structure
struct ThreadParam {
    int id;
    std::string message;
};

class ThreadManager {
private:
    std::vector<HANDLE> threadHandles;
    std::vector<DWORD> threadIds;
    std::vector<ThreadParam*> threadParams;

public:
    ThreadManager() {}
    
    ~ThreadManager() {
        // Clean up all threads
        terminateAll();
        
        // Clean up thread parameters
        for (ThreadParam* param : threadParams) {
            delete param;
        }
        threadParams.clear();
    }
    
    // Create a new thread
    bool create(LPTHREAD_START_ROUTINE threadFunction, LPVOID threadParam) {
        HANDLE threadHandle;
        DWORD threadId;
        
        threadHandle = CreateThread(NULL, 0, threadFunction, threadParam, 0, &threadId);
        if (threadHandle == NULL) {
            DWORD error = GetLastError();
            std::cerr << "Failed to create thread. Error: " << error << std::endl;
            return false;
        }
        
        threadHandles.push_back(threadHandle);
        threadIds.push_back(threadId);
        std::cout << "Created thread with ID " << threadId << std::endl;
        return true;
    }
    
    // Create a new thread with a parameter
    bool createWithParam(int id, const std::string& message) {
        ThreadParam* param = new ThreadParam();
        param->id = id;
        param->message = message;
        
        threadParams.push_back(param);
        
        return create(ThreadFunction, param);
    }
    
    // Create a suspended thread
    bool createSuspended(LPTHREAD_START_ROUTINE threadFunction, LPVOID threadParam) {
        HANDLE threadHandle;
        DWORD threadId;
        
        threadHandle = CreateThread(NULL, 0, threadFunction, threadParam, CREATE_SUSPENDED, &threadId);
        if (threadHandle == NULL) {
            DWORD error = GetLastError();
            std::cerr << "Failed to create suspended thread. Error: " << error << std::endl;
            return false;
        }
        
        threadHandles.push_back(threadHandle);
        threadIds.push_back(threadId);
        std::cout << "Created suspended thread with ID " << threadId << std::endl;
        return true;
    }
    
    // Resume a suspended thread
    bool resume(size_t index) {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return false;
        }
        
        DWORD result = ResumeThread(threadHandles[index]);
        if (result == (DWORD)-1) {
            DWORD error = GetLastError();
            std::cerr << "Failed to resume thread. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Resumed thread with ID " << threadIds[index] << std::endl;
        return true;
    }
    
    // Suspend a thread
    bool suspend(size_t index) {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return false;
        }
        
        DWORD result = SuspendThread(threadHandles[index]);
        if (result == (DWORD)-1) {
            DWORD error = GetLastError();
            std::cerr << "Failed to suspend thread. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Suspended thread with ID " << threadIds[index] << std::endl;
        return true;
    }
    
    // Wait for a thread to exit
    bool wait(size_t index, DWORD timeout = INFINITE) {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return false;
        }
        
        DWORD result = WaitForSingleObject(threadHandles[index], timeout);
        if (result == WAIT_OBJECT_0) {
            std::cout << "Thread with ID " << threadIds[index] << " exited" << std::endl;
            return true;
        } else if (result == WAIT_TIMEOUT) {
            std::cout << "Wait timed out for thread with ID " << threadIds[index] << std::endl;
            return false;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to wait for thread. Error: " << error << std::endl;
            return false;
        }
    }
    
    // Wait for all threads to exit
    bool waitAll(DWORD timeout = INFINITE) {
        if (threadHandles.empty()) {
            std::cout << "No threads to wait for" << std::endl;
            return true;
        }
        
        DWORD result = WaitForMultipleObjects(threadHandles.size(), threadHandles.data(), TRUE, timeout);
        if (result == WAIT_OBJECT_0) {
            std::cout << "All threads exited" << std::endl;
            return true;
        } else if (result == WAIT_TIMEOUT) {
            std::cout << "Wait timed out for all threads" << std::endl;
            return false;
        } else {
            DWORD error = GetLastError();
            std::cerr << "Failed to wait for all threads. Error: " << error << std::endl;
            return false;
        }
    }
    
    // Terminate a thread
    bool terminate(size_t index, DWORD exitCode = 0) {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return false;
        }
        
        if (!TerminateThread(threadHandles[index], exitCode)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to terminate thread. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Terminated thread with ID " << threadIds[index] << std::endl;
        
        // Clean up the thread handle
        CloseHandle(threadHandles[index]);
        
        // Remove the thread from the vectors
        threadHandles.erase(threadHandles.begin() + index);
        threadIds.erase(threadIds.begin() + index);
        
        return true;
    }
    
    // Terminate all threads
    void terminateAll(DWORD exitCode = 0) {
        while (!threadHandles.empty()) {
            terminate(0, exitCode);
        }
    }
    
    // Get the exit code of a thread
    DWORD getExitCode(size_t index) {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return 0;
        }
        
        DWORD exitCode;
        if (!GetExitCodeThread(threadHandles[index], &exitCode)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to get thread exit code. Error: " << error << std::endl;
            return 0;
        }
        
        if (exitCode == STILL_ACTIVE) {
            std::cout << "Thread with ID " << threadIds[index] << " is still running" << std::endl;
        } else {
            std::cout << "Thread with ID " << threadIds[index] << " exit code: " << exitCode << std::endl;
        }
        
        return exitCode;
    }
    
    // Get the number of threads
    size_t getThreadCount() const {
        return threadHandles.size();
    }
    
    // Get a thread handle
    HANDLE getThreadHandle(size_t index) const {
        if (index >= threadHandles.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return NULL;
        }
        
        return threadHandles[index];
    }
    
    // Get a thread ID
    DWORD getThreadId(size_t index) const {
        if (index >= threadIds.size()) {
            std::cerr << "Invalid thread index" << std::endl;
            return 0;
        }
        
        return threadIds[index];
    }
    
    // Create a remote thread in another process
    static HANDLE createRemoteThread(HANDLE processHandle, LPTHREAD_START_ROUTINE threadFunction, LPVOID threadParam) {
        DWORD threadId;
        HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, 0, threadFunction, threadParam, 0, &threadId);
        
        if (threadHandle == NULL) {
            DWORD error = GetLastError();
            std::cerr << "Failed to create remote thread. Error: " << error << std::endl;
            return NULL;
        }
        
        std::cout << "Created remote thread with ID " << threadId << std::endl;
        return threadHandle;
    }
};

// Thread function
DWORD WINAPI ThreadFunction(LPVOID lpParam) {
    ThreadParam* param = static_cast<ThreadParam*>(lpParam);
    
    std::cout << "Thread " << param->id << " started with message: " << param->message << std::endl;
    
    // Simulate some work
    for (int i = 0; i < 5; ++i) {
        std::cout << "Thread " << param->id << " working... " << i + 1 << "/5" << std::endl;
        Sleep(1000);
    }
    
    std::cout << "Thread " << param->id << " finished" << std::endl;
    
    return 0;
}

int main() {
    // Create a thread manager
    ThreadManager threadManager;
    
    // Create some threads
    threadManager.createWithParam(1, "Hello from thread 1");
    threadManager.createWithParam(2, "Hello from thread 2");
    
    // Create a suspended thread
    threadManager.createSuspended(ThreadFunction, new ThreadParam{3, "Hello from thread 3"});
    
    // Wait for a bit
    Sleep(2000);
    
    // Resume the suspended thread
    threadManager.resume(2);
    
    // Wait for all threads to exit
    threadManager.waitAll();
    
    std::cout << "All threads have exited" << std::endl;
    
    std::cout << "Note: This example is for educational purposes only." << std::endl;
    std::cout << "Always ensure you have proper authorization before manipulating threads." << std::endl;
    
    return 0;
}

