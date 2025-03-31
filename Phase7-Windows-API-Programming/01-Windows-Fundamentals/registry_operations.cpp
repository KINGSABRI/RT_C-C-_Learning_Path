#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

// Red Team Focus: Registry operations can be used to:
// 1. Implement persistence mechanisms
// 2. Store configuration data
// 3. Modify system behavior
// 4. Gather system information

class RegistryOperations {
private:
    HKEY hKey;
    bool isOpen;
    std::string keyPath;

public:
    RegistryOperations() : hKey(NULL), isOpen(false) {}
    
    ~RegistryOperations() {
        close();
    }
    
    // Open a registry key
    bool openKey(HKEY rootKey, const std::string& subKey, REGSAM access = KEY_READ | KEY_WRITE) {
        // Close any existing key
        close();
        
        keyPath = subKey;
        
        // Open the key
        LONG result = RegOpenKeyExA(rootKey, subKey.c_str(), 0, access, &hKey);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to open registry key: " << subKey << ". Error: " << result << std::endl;
            return false;
        }
        
        isOpen = true;
        std::cout << "Opened registry key: " << subKey << std::endl;
        return true;
    }
    
    // Create a registry key
    bool createKey(HKEY rootKey, const std::string& subKey, REGSAM access = KEY_READ | KEY_WRITE) {
        // Close any existing key
        close();
        
        keyPath = subKey;
        
        // Create the key
        DWORD disposition;
        LONG result = RegCreateKeyExA(rootKey, subKey.c_str(), 0, NULL, 0, access, NULL, &hKey, &disposition);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to create registry key: " << subKey << ". Error: " << result << std::endl;
            return false;
        }
        
        isOpen = true;
        std::cout << "Created registry key: " << subKey << std::endl;
        return true;
    }
    
    // Close the registry key
    void close() {
        if (isOpen && hKey != NULL) {
            RegCloseKey(hKey);
            hKey = NULL;
            isOpen = false;
            std::cout << "Closed registry key: " << keyPath << std::endl;
        }
    }
    
    // Set a string value
    bool setStringValue(const std::string& valueName, const std::string& value) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return false;
        }
        
        LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, 
                                   (const BYTE*)value.c_str(), value.length() + 1);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to set string value: " << valueName << ". Error: " << result << std::endl;
            return false;
        }
        
        std::cout << "Set string value: " << valueName << " = " << value << std::endl;
        return true;
    }
    
    // Set a DWORD value
    bool setDwordValue(const std::string& valueName, DWORD value) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return false;
        }
        
        LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_DWORD, 
                                   (const BYTE*)&value, sizeof(DWORD));
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to set DWORD value: " << valueName << ". Error: " << result << std::endl;
            return false;
        }
        
        std::cout << "Set DWORD value: " << valueName << " = " << value << std::endl;
        return true;
    }
    
    // Set a binary value
    bool setBinaryValue(const std::string& valueName, const std::vector<BYTE>& value) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return false;
        }
        
        LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_BINARY, 
                                   value.data(), value.size());
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to set binary value: " << valueName << ". Error: " << result << std::endl;
            return false;
        }
        
        std::cout << "Set binary value: " << valueName << " (" << value.size() << " bytes)" << std::endl;
        return true;
    }
    
    // Get a string value
    std::string getStringValue(const std::string& valueName) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return "";
        }
        
        DWORD type;
        DWORD dataSize = 0;
        
        // Get the data size
        LONG result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, NULL, &dataSize);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get string value size: " << valueName << ". Error: " << result << std::endl;
            return "";
        }
        
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            std::cerr << "Value is not a string: " << valueName << std::endl;
            return "";
        }
        
        // Allocate a buffer for the data
        std::vector<char> data(dataSize);
        
        // Get the data
        result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, (LPBYTE)data.data(), &dataSize);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get string value: " << valueName << ". Error: " << result << std::endl;
            return "";
        }
        
        std::string value(data.data());
        std::cout << "Got string value: " << valueName << " = " << value << std::endl;
        return value;
    }
    
    // Get a DWORD value
    DWORD getDwordValue(const std::string& valueName) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return 0;
        }
        
        DWORD type;
        DWORD dataSize = sizeof(DWORD);
        DWORD value = 0;
        
        // Get the data
        LONG result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, (LPBYTE)&value, &dataSize);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get DWORD value: " << valueName << ". Error: " << result << std::endl;
            return 0;
        }
        
        if (type != REG_DWORD) {
            std::cerr << "Value is not a DWORD: " << valueName << std::endl;
            return 0;
        }
        
        std::cout << "Got DWORD value: " << valueName << " = " << value << std::endl;
        return value;
    }
    
    // Get a binary value
    std::vector<BYTE> getBinaryValue(const std::string& valueName) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return std::vector<BYTE>();
        }
        
        DWORD type;
        DWORD dataSize = 0;
        
        // Get the data size
        LONG result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, NULL, &dataSize);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get binary value size: " << valueName << ". Error: " << result << std::endl;
            return std::vector<BYTE>();
        }
        
        if (type != REG_BINARY) {
            std::cerr << "Value is not binary: " << valueName << std::endl;
            return std::vector<BYTE>();
        }
        
        // Allocate a buffer for the data
        std::vector<BYTE> data(dataSize);
        
        // Get the data
        result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, data.data(), &dataSize);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get binary value: " << valueName << ". Error: " << result << std::endl;
            return std::vector<BYTE>();
        }
        
        std::cout << "Got binary value: " << valueName << " (" << data.size() << " bytes)" << std::endl;
        return data;
    }
    
    // Delete a value
    bool deleteValue(const std::string& valueName) {
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return false;
        }
        
        LONG result = RegDeleteValueA(hKey, valueName.c_str());
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to delete value: " << valueName << ". Error: " << result << std::endl;
            return false;
        }
        
        std::cout << "Deleted value: " << valueName << std::endl;
        return true;
    }
    
    // Delete a key
    static bool deleteKey(HKEY rootKey, const std::string& subKey) {
        LONG result = RegDeleteKeyA(rootKey, subKey.c_str());
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to delete key: " << subKey << ". Error: " << result << std::endl;
            return false;
        }
        
        std::cout << "Deleted key: " << subKey << std::endl;
        return true;
    }
    
    // Enumerate subkeys
    std::vector<std::string> enumSubKeys() {
        std::vector<std::string> subKeys;
        
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return subKeys;
        }
        
        DWORD index = 0;
        char keyName[MAX_PATH];
        DWORD keyNameSize = MAX_PATH;
        
        while (RegEnumKeyExA(hKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            subKeys.push_back(keyName);
            keyNameSize = MAX_PATH;
            index++;
        }
        
        std::cout << "Enumerated " << subKeys.size() << " subkeys" << std::endl;
        return subKeys;
    }
    
    // Enumerate values
    std::vector<std::string> enumValues() {
        std::vector<std::string> values;
        
        if (!isOpen || hKey == NULL) {
            std::cerr << "Registry key not open" << std::endl;
            return values;
        }
        
        DWORD index = 0;
        char valueName[MAX_PATH];
        DWORD valueNameSize = MAX_PATH;
        
        while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            values.push_back(valueName);
            valueNameSize = MAX_PATH;
            index++;
        }
        
        std::cout << "Enumerated " << values.size() << " values" << std::endl;
        return values;
    }
};

int main() {
    // Create a registry operations object
    RegistryOperations registry;
    
    // Create a test key
    std::string testKey = "Software\\RedTeamTest";
    if (registry.createKey(HKEY_CURRENT_USER, testKey)) {
        // Set some values
        registry.setStringValue("TestString", "Hello, World!");
        registry.setDwordValue("TestDword", 12345);
        
        std::vector<BYTE> binaryData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        registry.setBinaryValue("TestBinary", binaryData);
        
        // Read the values back
        std::string stringValue = registry.getStringValue("TestString");
        DWORD dwordValue = registry.getDwordValue("TestDword");
        std::vector<BYTE> binaryValue = registry.getBinaryValue("TestBinary");
        
        // Print the binary value
        std::cout << "Binary value bytes: ";
        for (BYTE b : binaryValue) {
            std::cout << std::hex << (int)b << " ";
        }
        std::cout << std::dec << std::endl;
        
        // Enumerate subkeys and values
        std::vector<std::string> subKeys = registry.enumSubKeys();
        std::vector<std::string> values = registry.enumValues();
        
        // Print the subkeys
        std::cout << "Subkeys:" << std::endl;
        for (const std::string& subKey : subKeys) {
            std::cout << "  " << subKey << std::endl;
        }
        
        // Print the values
        std::cout << "Values:" << std::endl;
        for (const std::string& value : values) {
            std::cout << "  " << value << std::endl;
        }
        
        // Delete the values
        registry.deleteValue("TestString");
        registry.deleteValue("TestDword");
        registry.deleteValue("TestBinary");
        
        // Close the key
        registry.close();
        
        // Delete the key
        RegistryOperations::deleteKey(HKEY_CURRENT_USER, testKey);
    }
    
    std::cout << "Note: This example is for educational purposes only." << std::endl;
    std::cout << "Always ensure you have proper authorization before modifying the registry." << std::endl;
    
    return 0;
}

