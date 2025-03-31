/**
 * Basic TCP Server Implementation
 * 
 * This example demonstrates a secure TCP server implementation with:
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
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

// Global variables for cleanup
std::atomic<bool> running{true};
std::vector<int> client_sockets;
int server_socket = -1;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nShutting down server..." << std::endl;
    running = false;
    
    // Close all client connections
    for (int sock : client_sockets) {
        if (sock != -1) close(sock);
    }
    
    // Close server socket
    if (server_socket != -1) close(server_socket);
    
    exit(0);
}

// Function to handle client connections
void handle_client(int client_socket, const std::string& client_ip) {
    std::cout << "Client connected: " << client_ip << std::endl;
    
    // Set receive timeout
    struct timeval timeout;
    timeout.tv_sec = 60; // 60 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    char buffer[1024];
    std::string message;
    
    while (running) {
        // Clear the buffer
        memset(buffer, 0, sizeof(buffer));
        
        // Receive data from client
        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            // Connection closed or error
            if (bytes_received == 0) {
                std::cout << "Client disconnected: " << client_ip << std::endl;
            } else {
                std::cerr << "Error receiving data from client: " << client_ip << std::endl;
            }
            break;
        }
        
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
        
        // Input validation - check for malicious patterns
        // This is a simple example - real-world validation would be more comprehensive
        std::string input(buffer);
        if (input.find("../") != std::string::npos || input.find("..\\") != std::string::npos) {
            std::string error_msg = "Invalid input detected. Possible directory traversal attempt.";
            send(client_socket, error_msg.c_str(), error_msg.length(), 0);
            continue;
        }
        
        std::cout << "Received from " << client_ip << ": " << buffer << std::endl;
        
        // Process the message (echo in this example)
        message = "Server received: ";
        message += buffer;
        
        // Send response back to client
        send(client_socket, message.c_str(), message.length(), 0);
    }
    
    // Close the client socket
    close(client_socket);
    
    // Remove from the list of client sockets
    auto it = std::find(client_sockets.begin(), client_sockets.end(), client_socket);
    if (it != client_sockets.end()) {
        client_sockets.erase(it);
    }
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Default port
    int port = 8888;
    
    // Parse command line arguments
    if (argc > 1) {
        port = std::stoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number. Using default port 8888." << std::endl;
            port = 8888;
        }
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
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
    
    // Listen for incoming connections
    if (listen(server_socket, 5) < 0) {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        close(server_socket);
        return 1;
    }
    
    std::cout << "Server started on port " << port << std::endl;
    std::cout << "Press Ctrl+C to stop the server" << std::endl;
    
    // Accept and handle client connections
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept a new connection
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (errno == EINTR && !running) {
                // Interrupted by signal, and we're shutting down
                break;
            }
            std::cerr << "Accept failed: " << strerror(errno) << std::endl;
            continue;
        }
        
        // Get client IP address
        std::string client_ip = inet_ntoa(client_addr.sin_addr);
        
        // Add to the list of client sockets
        client_sockets.push_back(client_socket);
        
        // Create a new thread to handle the client
        std::thread client_thread(handle_client, client_socket, client_ip);
        client_thread.detach();
    }
    
    // Close the server socket
    close(server_socket);
    
    return 0;
}

