#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

// Red Team Focus: File operations can be used to:
// 1. Access sensitive files
// 2. Create and modify files for persistence
// 3. Extract information from the system
// 4. Implement file-based backdoors

class FileOperations {
private:
    HANDLE fileHandle;
    std::string filePath;
    bool isOpen;

public:
    FileOperations() : fileHandle(INVALID_HANDLE_VALUE), isOpen(false) {}
    
    ~FileOperations() {
        close();
    }
    
    // Open a file
    bool open(const std::string& path, DWORD access = GENERIC_READ | GENERIC_WRITE, 
        DWORD share = 0, DWORD creation = OPEN_EXISTING) {
        // Close any existing file
        close();
        
        filePath = path;
        
        // Open the file
        fileHandle = CreateFileA(path.c_str(), access, share, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to open file: " << path << ". Error: " << error << std::endl;
            return false;
        }
        
        isOpen = true;
        std::cout << "Opened file: " << path << std::endl;
        return true;
    }
    
    // Create a file
    bool create(const std::string& path, DWORD access = GENERIC_READ | GENERIC_WRITE, 
        DWORD share = 0) {
        return open(path, access, share, CREATE_ALWAYS);
    }
    
    // Close the file
    void close() {
        if (isOpen && fileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(fileHandle);
            fileHandle = INVALID_HANDLE_VALUE;
            isOpen = false;
            std::cout << "Closed file: " << filePath << std::endl;
        }
    }
    
    // Read from the file
    std::vector<BYTE> read(DWORD bytesToRead) {
        std::vector<BYTE> buffer;
        
        if (!isOpen || fileHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "File not open" << std::endl;
            return buffer;
        }
        
        buffer.resize(bytesToRead);
        DWORD bytesRead;
        
        if (!ReadFile(fileHandle, buffer.data(), bytesToRead, &bytesRead, NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to read from file. Error: " << error << std::endl;
            buffer.clear();
            return buffer;
        }
        
        // Resize the buffer to the actual number of bytes read
        buffer.resize(bytesRead);
        
        std::cout << "Read " << bytesRead << " bytes from file" << std::endl;
        return buffer;
    }
    
    // Read the entire file
    std::vector<BYTE> readAll() {
        if (!isOpen || fileHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "File not open" << std::endl;
            return std::vector<BYTE>();
        }
        
        // Get the file size
        DWORD fileSize = GetFileSize(fileHandle, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to get file size. Error: " << error << std::endl;
            return std::vector<BYTE>();
        }
        
        // Set the file pointer to the beginning
        SetFilePointer(fileHandle, 0, NULL, FILE_BEGIN);
        
        // Read the entire file
        return read(fileSize);
    }
    
    // Write to the file
    bool write(const std::vector<BYTE>& data) {
        if (!isOpen || fileHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "File not open" << std::endl;
            return false;
        }
        
        DWORD bytesWritten;
        
        if (!WriteFile(fileHandle, data.data(), data.size(), &bytesWritten, NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to write to file. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Wrote " << bytesWritten << " bytes to file" << std::endl;
        return bytesWritten == data.size();
    }
    
    // Write a string to the file
    bool writeString(const std::string& str) {
        std::vector<BYTE> data(str.begin(), str.end());
        return write(data);
    }
    
    // Set the file pointer
    bool setFilePointer(LONG distance, DWORD moveMethod = FILE_BEGIN) {
        if (!isOpen || fileHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "File not open" << std::endl;
            return false;
        }
        
        DWORD result = SetFilePointer(fileHandle, distance, NULL, moveMethod);
        if (result == INVALID_SET_FILE_POINTER) {
            DWORD error = GetLastError();
            std::cerr << "Failed to set file pointer. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Set file pointer to " << result << std::endl;
        return true;
    }
    
    // Get the file size
    DWORD getFileSize() {
        if (!isOpen || fileHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "File not open" << std::endl;
            return 0;
        }
        
        DWORD fileSize = ::GetFileSize(fileHandle, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to get file size. Error: " << error << std::endl;
            return 0;
        }
        
        std::cout << "File size: " << fileSize << " bytes" << std::endl;
        return fileSize;
    }
    
    // Delete a file
    static bool deleteFile(const std::string& path) {
        if (!DeleteFileA(path.c_str())) {
            DWORD error = GetLastError();
            std::cerr << "Failed to delete file: " << path << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Deleted file: " << path << std::endl;
        return true;
    }
    
    // Check if a file exists
    static bool fileExists(const std::string& path) {
        DWORD attributes = GetFileAttributesA(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
    }
    
    // Get file attributes
    static DWORD getFileAttributes(const std::string& path) {
        DWORD attributes = GetFileAttributesA(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            std::cerr << "Failed to get file attributes: " << path << ". Error: " << error << std::endl;
            return 0;
        }
        
        std::cout << "File attributes: " << attributes << std::endl;
        return attributes;
    }
    
    // Set file attributes
    static bool setFileAttributes(const std::string& path, DWORD attributes) {
        if (!SetFileAttributesA(path.c_str(), attributes)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to set file attributes: " << path << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Set file attributes: " << attributes << std::endl;
        return true;
    }
    
    // Copy a file
    static bool copyFile(const std::string& sourcePath, const std::string& destinationPath, bool failIfExists = false) {
        if (!CopyFileA(sourcePath.c_str(), destinationPath.c_str(), failIfExists)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to copy file: " << sourcePath << " to " << destinationPath << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Copied file: " << sourcePath << " to " << destinationPath << std::endl;
        return true;
    }
    
    // Move a file
    static bool moveFile(const std::string& sourcePath, const std::string& destinationPath) {
        if (!MoveFileA(sourcePath.c_str(), destinationPath.c_str())) {
            DWORD error = GetLastError();
            std::cerr << "Failed to move file: " << sourcePath << " to " << destinationPath << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Moved file: " << sourcePath << " to " << destinationPath << std::endl;
        return true;
    }
    
    // Create a directory
    static bool createDirectory(const std::string& path) {
        if (!CreateDirectoryA(path.c_str(), NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to create directory: " << path << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Created directory: " << path << std::endl;
        return true;
    }
    
    // Remove a directory
    static bool removeDirectory(const std::string& path) {
        if (!RemoveDirectoryA(path.c_str())) {
            DWORD error = GetLastError();
            std::cerr << "Failed to remove directory: " << path << ". Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Removed directory: " << path << std::endl;
        return true;
    }
};

int main() {
    // Create a file operations object
    FileOperations fileOps;
    
    // Create a test file
    std::string testFile = "test.txt";
    if (fileOps.create(testFile)) {
        // Write some data to the file
        fileOps.writeString("Hello, World!\nThis is a test file.\n");
        
        // Set the file pointer to the beginning
        fileOps.setFilePointer(0);
        
        // Read the data back
        std::vector<BYTE> data = fileOps.readAll();
        
        // Print the data as a string
        std::string dataStr(data.begin(), data.end());
        std::cout << "File contents:\n" << dataStr << std::endl;
        
        // Close the file
        fileOps.close();
        
        // Get the file attributes
        DWORD attributes = FileOperations::getFileAttributes(testFile);
        
        // Set the file to read-only
        FileOperations::setFileAttributes(testFile, attributes | FILE_ATTRIBUTE_READONLY);
        
        // Try to open the file for writing (should fail)
        if (!fileOps.open(testFile)) {
            std::cout << "Failed to open read-only file for writing (as expected)" << std::endl;
        }
        
        // Set the file back to normal
        FileOperations::setFileAttributes(testFile, attributes);
        
        // Copy the file
        std::string copyFile = "test_copy.txt";
        FileOperations::copyFile(testFile, copyFile);
        
        // Move the copy
        std::string movedFile = "test_moved.txt";
        FileOperations::moveFile(copyFile, movedFile);
        
        // Delete the files
        FileOperations::deleteFile(testFile);
        FileOperations::deleteFile(movedFile);
    }
    
    // Create and remove a directory
    std::string testDir = "test_dir";
    if (FileOperations::createDirectory(testDir)) {
        FileOperations::removeDirectory(testDir);
    }
    
    std::cout << "Note: This example is for educational purposes only." << std::endl;
    std::cout << "Always ensure you have proper authorization before accessing files." << std::endl;
    
    return 0;
}

