/**
 * Custom Protocol Implementation
 * 
 * This example demonstrates a simple custom protocol with:
 * - Protocol specification
 * - Message format
 * - Serialization/deserialization
 * - Security considerations
 * 
 * For educational purposes only.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <cstdint>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

/**
 * SecureProtocol - A simple secure communication protocol
 * 
 * Protocol Format:
 * +----------------+----------------+----------------+----------------+
 * | Magic (4 bytes)| Version (1 byte)| Type (1 byte) | Flags (1 byte) |
 * +----------------+----------------+----------------+----------------+
 * | Sequence (4 bytes)             | Timestamp (8 bytes)              |
 * +----------------+----------------+----------------+----------------+
 * | Payload Length (4 bytes)       | HMAC Length (1 byte)             |
 * +----------------+----------------+----------------+----------------+
 * | Payload Data (variable)                                           |
 * +----------------+----------------+----------------+----------------+
 * | HMAC (variable)                                                   |
 * +----------------+----------------+----------------+----------------+
 */

// Protocol constants
const uint32_t PROTOCOL_MAGIC = 0x53505054;  // "SPPT"
const uint8_t PROTOCOL_VERSION = 0x01;

// Message types
enum class MessageType : uint8_t {
    HELLO = 0x01,
    DATA = 0x02,
    ACK = 0x03,
    ERROR = 0x04,
    GOODBYE = 0x05
};

// Flag bits
const uint8_t FLAG_ENCRYPTED = 0x01;
const uint8_t FLAG_COMPRESSED = 0x02;
const uint8_t FLAG_URGENT = 0x04;
const uint8_t FLAG_FRAGMENTED = 0x08;
const uint8_t FLAG_LAST_FRAGMENT = 0x10;

// Error codes
enum class ErrorCode : uint8_t {
    NONE = 0x00,
    INVALID_MESSAGE = 0x01,
    PROTOCOL_ERROR = 0x02,
    AUTH_FAILED = 0x03,
    INTERNAL_ERROR = 0x04,
    RESOURCE_UNAVAILABLE = 0x05
};

// Message header structure
struct MessageHeader {
    uint32_t magic;
    uint8_t version;
    MessageType type;
    uint8_t flags;
    uint32_t sequence;
    uint64_t timestamp;
    uint32_t payload_length;
    uint8_t hmac_length;
};

// Message structure
struct Message {
    MessageHeader header;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> hmac;
};

// Simple HMAC function (for demonstration only - not cryptographically secure)
std::vector<uint8_t> calculate_hmac(const std::vector<uint8_t>& data, const std::string& key) {
    // In a real implementation, use a proper HMAC algorithm like HMAC-SHA256
    // This is a simplified version for demonstration
    std::vector<uint8_t> hmac(16, 0);
    
    // Convert key to bytes
    std::vector<uint8_t> key_bytes(key.begin(), key.end());
    
    // Simple mixing function
    for (size_t i = 0; i < data.size(); ++i) {
        hmac[i % 16] ^= data[i];
        hmac[(i + 1) % 16] += data[i] + key_bytes[i % key_bytes.size()];
        hmac[(i + 2) % 16] = (hmac[(i + 2) % 16] << 1) | (hmac[(i + 2) % 16] >> 7);
    }
    
    return hmac;
}

// Function to serialize a message to bytes
std::vector<uint8_t> serialize_message(const Message& message, const std::string& key) {
    std::vector<uint8_t> result;
    
    // Add header fields
    result.push_back((message.header.magic >> 24) & 0xFF);
    result.push_back((message.header.magic >> 16) & 0xFF);
    result.push_back((message.header.magic >> 8) & 0xFF);
    result.push_back(message.header.magic & 0xFF);
    
    result.push_back(message.header.version);
    result.push_back(static_cast<uint8_t>(message.header.type));
    result.push_back(message.header.flags);
    
    result.push_back((message.header.sequence >> 24) & 0xFF);
    result.push_back((message.header.sequence >> 16) & 0xFF);
    result.push_back((message.header.sequence >> 8) & 0xFF);
    result.push_back(message.header.sequence & 0xFF);
    
    for (int i = 7; i >= 0; --i) {
        result.push_back((message.header.timestamp >> (i * 8)) & 0xFF);
    }
    
    result.push_back((message.header.payload_length >> 24) & 0xFF);
    result.push_back((message.header.payload_length >> 16) & 0xFF);
    result.push_back((message.header.payload_length >> 8) & 0xFF);
    result.push_back(message.header.payload_length & 0xFF);
    
    result.push_back(message.header.hmac_length);
    
    // Add payload
    result.insert(result.end(), message.payload.begin(), message.payload.end());
    
    // Calculate and add HMAC
    std::vector<uint8_t> hmac = calculate_hmac(result, key);
    result.insert(result.end(), hmac.begin(), hmac.end());
    
    return result;
}

// Function to deserialize bytes to a message
Message deserialize_message(const std::vector<uint8_t>& data, const std::string& key, bool& valid) {
    Message message;
    valid = false;
    
    // Check minimum length
    if (data.size() < 24) {
        std::cerr << "Message too short" << std::endl;
        return message;
    }
    
    // Parse header
    size_t offset = 0;
    
    message.header.magic = (data[offset] << 24) | (data[offset + 1] << 16) | 
                          (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    // Validate magic number
    if (message.header.magic != PROTOCOL_MAGIC) {
        std::cerr << "Invalid magic number" << std::endl;
        return message;
    }
    
    message.header.version = data[offset++];
    message.header.type = static_cast<MessageType>(data[offset++]);
    message.header.flags = data[offset++];
    
    message.header.sequence = (data[offset] << 24) | (data[offset + 1] << 16) | 
                             (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    message.header.timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        message.header.timestamp = (message.header.timestamp << 8) | data[offset++];
    }
    
    message.header.payload_length = (data[offset] << 24) | (data[offset + 1] << 16) | 
                                   (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    message.header.hmac_length = data[offset++];
    
    // Validate lengths
    if (data.size() < offset + message.header.payload_length + message.header.hmac_length) {
        std::cerr << "Message truncated" << std::endl;
        return message;
    }
    
    // Extract payload
    message.payload.assign(data.begin() + offset, 
                          data.begin() + offset + message.header.payload_length);
    offset += message.header.payload_length;
    
    // Extract HMAC
    message.hmac.assign(data.begin() + offset, 
                       data.begin() + offset + message.header.hmac_length);
    
    // Verify HMAC
    std::vector<uint8_t> data_to_verify(data.begin(), 
                                       data.begin() + offset);
    std::vector<uint8_t> calculated_hmac = calculate_hmac(data_to_verify, key);
    
    if (calculated_hmac != message.hmac) {
        std::cerr << "HMAC verification failed" << std::endl;
        return message;
    }
    
    valid = true;
    return message;
}

// Function to create a message
Message create_message(MessageType type, const std::vector<uint8_t>& payload, 
                      uint32_t sequence, uint8_t flags = 0) {
    Message message;
    
    message.header.magic = PROTOCOL_MAGIC;
    message.header.version = PROTOCOL_VERSION;
    message.header.type = type;
    message.header.flags = flags;
    message.header.sequence = sequence;
    message.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    message.header.payload_length = payload.size();
    message.header.hmac_length = 16;  // Fixed size for our simple HMAC
    
    message.payload = payload;
    
    return message;
}

// Function to create a string payload
std::vector<uint8_t> create_string_payload(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

// Function to extract string from payload
std::string extract_string_payload(const std::vector<uint8_t>& payload) {
    return std::string(payload.begin(), payload.end());
}

// Function to create an error message
Message create_error_message(ErrorCode code, const std::string& error_message, uint32_t sequence) {
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(code));
    
    std::vector<uint8_t> message_bytes(error_message.begin(), error_message.end());
    payload.insert(payload.end(), message_bytes.begin(), message_bytes.end());
    
    return create_message(MessageType::ERROR, payload, sequence);
}

// Function to extract error details from an error message
std::pair<ErrorCode, std::string> extract_error_details(const Message& message) {
    if (message.header.type != MessageType::ERROR || message.payload.empty()) {
        return {ErrorCode::NONE, ""};
    }
    
    ErrorCode code = static_cast<ErrorCode>(message.payload[0]);
    std::string error_message;
    
    if (message.payload.size() > 1) {
        error_message = std::string(message.payload.begin() + 1, message.payload.end());
    }
    
    return {code, error_message};
}

// Function to print message details
void print_message(const Message& message) {
    std::cout << "Message Details:" << std::endl;
    std::cout << "  Magic: 0x" << std::hex << std::setw(8) << std::setfill('0') 
              << message.header.magic << std::dec << std::endl;
    std::cout << "  Version: " << static_cast<int>(message.header.version) << std::endl;
    
    std::cout << "  Type: ";
    switch (message.header.type) {
        case MessageType::HELLO: std::cout << "HELLO"; break;
        case MessageType::DATA: std::cout << "DATA"; break;
        case MessageType::ACK: std::cout << "ACK"; break;
        case MessageType::ERROR: std::cout << "ERROR"; break;
        case MessageType::GOODBYE: std::cout << "GOODBYE"; break;
        default: std::cout << "UNKNOWN"; break;
    }
    std::cout << " (0x" << std::hex << static_cast<int>(static_cast<uint8_t>(message.header.type)) 
              << std::dec << ")" << std::endl;
    
    std::cout << "  Flags: 0x" << std::hex << static_cast<int>(message.header.flags) << std::dec << " (";
    if (message.header.flags & FLAG_ENCRYPTED) std::cout << "ENCRYPTED ";
    if (message.header.flags & FLAG_COMPRESSED) std::cout << "COMPRESSED ";
    if (message.header.flags & FLAG_URGENT) std::cout << "URGENT ";
    if (message.header.flags & FLAG_FRAGMENTED) std::cout << "FRAGMENTED ";
    if (message.header.flags & FLAG_LAST_FRAGMENT) std::cout << "LAST_FRAGMENT ";
    std::cout << ")" << std::endl;
    
    std::cout << "  Sequence: " << message.header.sequence << std::endl;
    
    // Convert timestamp to human-readable format
    auto time_point = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(message.header.timestamp));
    auto time_t = std::chrono::system_clock::to_time_t(time_point);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    std::cout << "  Timestamp: " << message.header.timestamp << " (" << ss.str() << ")" << std::endl;
    
    std::cout << "  Payload Length: " << message.header.payload_length << " bytes" << std::endl;
    std::cout << "  HMAC Length: " << static_cast<int>(message.header.hmac_length) << " bytes" << std::endl;
    
    // Print payload as string if it's printable
    bool printable = true;
    for (uint8_t byte : message.payload) {
        if (byte < 32 || byte > 126) {
            printable = false;
            break;
        }
    }
    
    if (printable && !message.payload.empty()) {
        std::cout << "  Payload (as string): \"" 
                  << std::string(message.payload.begin(), message.payload.end()) << "\"" << std::endl;
    } else if (!message.payload.empty()) {
        std::cout << "  Payload (hex): ";
        for (size_t i = 0; i < std::min(message.payload.size(), size_t(16)); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(message.payload[i]) << " ";
        }
        if (message.payload.size() > 16) {
            std::cout << "...";
        }
        std::cout << std::dec << std::endl;
    }
    
    // If it's an error message, decode it
    if (message.header.type == MessageType::ERROR) {
        auto [code, error_message] = extract_error_details(message);
        std::cout << "  Error Code: ";
        switch (code) {
            case ErrorCode::INVALID_MESSAGE: std::cout << "INVALID_MESSAGE"; break;
            case ErrorCode::PROTOCOL_ERROR: std::cout << "PROTOCOL_ERROR"; break;
            case ErrorCode::AUTH_FAILED: std::cout << "AUTH_FAILED"; break;
            case ErrorCode::INTERNAL_ERROR: std::cout << "INTERNAL_ERROR"; break;
            case ErrorCode::RESOURCE_UNAVAILABLE: std::cout << "RESOURCE_UNAVAILABLE"; break;
            default: std::cout << "UNKNOWN"; break;
        }
        std::cout << " (0x" << std::hex << static_cast<int>(static_cast<uint8_t>(code)) 
                  << std::dec << ")" << std::endl;
        std::cout << "  Error Message: " << error_message << std::endl;
    }
}

// Example usage
int main() {
    // Shared secret key (in a real application, this would be securely exchanged)
    std::string secret_key = "ThisIsASecretKey123";
    
    // Create a sequence number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(1, 1000000);
    uint32_t sequence = dis(gen);
    
    std::cout << "Custom Protocol Demonstration" << std::endl;
    std::cout << "----------------------------" << std::endl;
    
    // Example 1: Create and send a HELLO message
    std::cout << "\nExample 1: HELLO Message" << std::endl;
    
    // Create payload with client information
    std::string client_info = "ClientID=12345;Version=1.0;Capabilities=Encryption,Compression";
    std::vector<uint8_t> hello_payload = create_string_payload(client_info);
    
    // Create message
    Message hello_message = create_message(MessageType::HELLO, hello_payload, sequence++);
    
    // Serialize message
    std::vector<uint8_t> serialized_hello = serialize_message(hello_message, secret_key);
    
    std::cout << "Serialized HELLO message: " << serialized_hello.size() << " bytes" << std::endl;
    
    // Deserialize and verify message
    bool valid;
    Message received_hello = deserialize_message(serialized_hello, secret_key, valid);
    
    if (valid) {
        std::cout << "HELLO message successfully verified" << std::endl;
        print_message(received_hello);
    } else {
        std::cout << "HELLO message verification failed" << std::endl;
    }
    
    // Example 2: Create and send a DATA message with encryption flag
    std::cout << "\nExample 2: DATA Message (with encryption flag)" << std::endl;
    
    // Create payload with some data
    std::string data = "This is some sensitive data that would be encrypted in a real implementation";
    std::vector<uint8_t> data_payload = create_string_payload(data);
    
    // Create message with encryption flag
    Message data_message = create_message(MessageType::DATA, data_payload, sequence++, FLAG_ENCRYPTED);
    
    // Serialize message
    std::vector<uint8_t> serialized_data = serialize_message(data_message, secret_key);
    
    std::cout << "Serialized DATA message: " << serialized_data.size() << " bytes" << std::endl;
    
    // Deserialize and verify message
    Message received_data = deserialize_message(serialized_data, secret_key, valid);
    
    if (valid) {
        std::cout << "DATA message successfully verified" << std::endl;
        print_message(received_data);
    } else {
        std::cout << "DATA message verification failed" << std::endl;
    }
    
    // Example 3: Create and send an ERROR message
    std::cout << "\nExample 3: ERROR Message" << std::endl;
    
    // Create error message
    Message error_message = create_error_message(
        ErrorCode::AUTH_FAILED, 
        "Invalid credentials provided", 
        sequence++
    );
    
    // Serialize message
    std::vector<uint8_t> serialized_error = serialize_message(error_message, secret_key);
    
    std::cout << "Serialized ERROR message: " << serialized_error.size() << " bytes" << std::endl;
    
    // Deserialize and verify message
    Message received_error = deserialize_message(serialized_error, secret_key, valid);
    
    if (valid) {
        std::cout << "ERROR message successfully verified" << std::endl;
        print_message(received_error);
    } else {
        std::cout << "ERROR message verification failed" << std::endl;
    }
    
    // Example 4: Tampered message (HMAC verification should fail)
    std::cout << "\nExample 4: Tampered Message" << std::endl;
    
    // Create a copy of the serialized data message and tamper with it
    std::vector<uint8_t> tampered_data = serialized_data;
    if (tampered_data.size() > 30) {
        tampered_data[30] ^= 0xFF;  // Flip all bits in one byte
    }
    
    // Deserialize and verify tampered message
    Message received_tampered = deserialize_message(tampered_data, secret_key, valid);
    
    if (valid) {
        std::cout << "WARNING: Tampered message verification succeeded (this should not happen)" << std::endl;
        print_message(received_tampered);
    } else {
        std::cout << "Tampered message verification failed (as expected)" << std::endl;
    }
    
    return 0;
}

