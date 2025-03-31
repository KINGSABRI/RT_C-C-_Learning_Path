/**
 * Basic TCP Client Implementation
 * 
 * This example demonstrates a secure TCP client implementation with:
 * - Proper error handling
 * - Connection timeout management
 * - Basic input validation
 * - Graceful shutdown
 * 
 * For educational purposes only.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>

// Global variables for cleanup
int client_socket = -1;
bool running = true;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nShutting down client..." << std::endl;
    running = false;
    
    // Close client socket
    if (client_socket != -1) close(client_socket);
    
    exit(0);
}

// Function to validate server response
bool validate_response(const std::string& response) {
    // Check for suspicious patterns in server response
    // This is a simple example - real-world validation would be more comprehensive
    if (response.find("error") != std::string::npos || 
        response.find("exception") != std::string::npos ||
        response.find("overflow") != std::string::npos) {
        std::cerr << "Warning: Server response contains suspicious patterns." << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Default values
    std::string server_ip = "127.0.0.1";
    int port = 8888;
    
    // Parse command line arguments
    if (argc > 1) server_ip = argv[1];
    if (argc > 2) {
        port = std::stoi(argv[2]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number. Using default port 8888." << std::endl;
            port = 8888;
        }
    }
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 10; // 10 seconds timeout
    timeout.tv_usec = 0;
    if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        std::cerr << "Failed to set receive timeout: " << strerror(errno) << std::endl;
    }
    if (setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        std::cerr << "Failed to set send timeout: " << strerror(errno) << std::endl;
    }
    
    // Prepare the sockaddr_in structure
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported: " << server_ip << std::endl;
        close(client_socket);
        return 1;
    }
    
    // Connect to the server
    std::cout << "Connecting to server at " << server_ip << ":" << port << "..." << std::endl;
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed: " << strerror(errno) << std::endl;
        close(client_socket);
        return 1;
    }
    
    std::cout << "Connected to server." << std::endl;
    std::cout << "Type your message (or 'exit' to quit):" << std::endl;
    
    char buffer[1024];
    std::string message;
    
    while (running) {
        // Get user input
        std::cout << "> ";
        std::getline(std::cin, message);
        
        // Check if user wants to exit
        if (message == "exit") {
            break;
        }
        
        // Send message to server
        if (send(client_socket, message.c_str(), message.length(), 0) < 0) {
            std::cerr << "Failed to send message: " << strerror(errno) << std::endl;
            break;
        }
        
        // Clear the buffer
        memset(buffer, 0, sizeof(buffer));
        
        // Receive response from server
        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received < 0) {
            std::cerr << "Failed to receive response: " << strerror(errno) << std::endl;
            break;
        } else if (bytes_received == 0) {
            std::cout << "Server closed the connection." << std::endl;
            break;
        }
        
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
        
        // Validate and display server response
        std::string response(buffer);
        if (validate_response(response)) {
            std::cout << "Server: " << buffer << std::endl;
        } else {
            std::cout << "Server sent a potentially unsafe response." << std::endl;
        }
    }
    
    // Close the client socket
    close(client_socket);
    
    return 0;
}

