/**
 * Basic UDP Server Implementation
 * 
 * This example demonstrates a secure UDP server implementation with:
 * - Proper error handling
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
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <atomic>

// Global variables for cleanup
std::atomic<bool> running{true};
int server_socket = -1;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nShutting down UDP server..." << std::endl;
    running = false;
    
    // Close server socket
    if (server_socket != -1) close(server_socket);
    
    exit(0);
}

// Function to validate client message
bool validate_message(const std::string& message) {
    // Check for suspicious patterns
    // This is a simple example - real-world validation would be more comprehensive
    if (message.find("../") != std::string::npos || 
        message.find("..\\") != std::string::npos ||
        message.find(";") != std::string::npos ||
        message.find("|") != std::string::npos) {
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Default port
    int port = 8889;
    
    // Parse command line arguments
    if (argc > 1) {
        port = std::stoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number. Using default port 8889." << std::endl;
            port = 8889;
        }
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket == -1) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options: " << strerror(errno) << std::endl;
        close(server_socket);
        return 1;
    }
    
    // Prepare the sockaddr_in structure
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Bind the socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(server_socket);
        return 1;
    }
    
    std::cout << "UDP Server started on port " << port << std::endl;
    std::cout << "Press Ctrl+C to stop the server" << std::endl;
    
    char buffer[1024];
    std::string message;
    
    while (running) {
        // Clear the buffer
        memset(buffer, 0, sizeof(buffer));
        
        // Client address
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Receive message from client
        ssize_t bytes_received = recvfrom(server_socket, buffer, sizeof(buffer) - 1, 0,
                                         (struct sockaddr*)&client_addr, &client_len);
        
        if (bytes_received < 0) {
            if (errno == EINTR && !running) {
                // Interrupted by signal, and we're shutting down
                break;
            }
            std::cerr << "Failed to receive data: " << strerror(errno) << std::endl;
            continue;
        }
        
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
        
        // Get client IP address
        std::string client_ip = inet_ntoa(client_addr.sin_addr);
        
        std::cout << "Received from " << client_ip << ":" << ntohs(client_addr.sin_port) 
                  << " - " << buffer << std::endl;
        
        // Validate the message
        std::string input(buffer);
        if (!validate_message(input)) {
            std::string error_msg = "Invalid input detected. Possible malicious content.";
            sendto(server_socket, error_msg.c_str(), error_msg.length(), 0,
                  (struct sockaddr*)&client_addr, client_len);
            continue;
        }
        
        // Process the message (echo in this example)
        message = "Server received: ";
        message += buffer;
        
        // Send response back to client
        sendto(server_socket, message.c_str(), message.length(), 0,
              (struct sockaddr*)&client_addr, client_len);
    }
    
    // Close the server socket
    close(server_socket);
    
    return 0;
}

