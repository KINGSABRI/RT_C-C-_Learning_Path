/**
 * Secure Connection Implementation with TLS
 * 
 * This example demonstrates a secure connection using OpenSSL:
 * - TLS/SSL implementation
 * - Certificate validation
 * - Secure data transmission
 * 
 * Requires OpenSSL development libraries
 * Compile with: g++ secure_connection.cpp -o secure_connection -lssl -lcrypto
 * 
 * For educational purposes only.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Function to initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Function to create SSL context
SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

// Function to configure SSL context
void configure_context(SSL_CTX* ctx) {
    // Set up certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // Set the default locations for trusted CA certificates
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        std::cerr << "Failed to set default CA locations" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Set the cipher list to use secure ciphers
    if (!SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")) {
        std::cerr << "Failed to set cipher list" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}

// Function to establish a secure connection
SSL* establish_secure_connection(SSL_CTX* ctx, const std::string& hostname, int port) {
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return nullptr;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert hostname to IP address
    if (inet_pton(AF_INET, hostname.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported: " << hostname << std::endl;
        close(sock);
        return nullptr;
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed: " << strerror(errno) << std::endl;
        close(sock);
        return nullptr;
    }
    
    // Create SSL object
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Failed to create SSL object" << std::endl;
        ERR_print_errors_fp(stderr);
        close(sock);
        return nullptr;
    }
    
    // Set the hostname for SNI (Server Name Indication)
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    
    // Set the hostname for certificate verification
    SSL_set1_host(ssl, hostname.c_str());
    
    // Attach the socket to the SSL object
    SSL_set_fd(ssl, sock);
    
    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL handshake failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }
    
    // Verify the certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "No certificate presented by the server" << std::endl;
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }
    
    // Free the certificate as we've verified it exists
    X509_free(cert);
    
    // Verify the certificate chain
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "Certificate verification failed" << std::endl;
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }
    
    std::cout << "Secure connection established with " << hostname << ":" << port << std::endl;
    std::cout << "Using cipher: " << SSL_get_cipher(ssl) << std::endl;
    
    return ssl;
}

// Function to send data securely
bool send_secure_data(SSL* ssl, const std::string& data) {
    int bytes_written = SSL_write(ssl, data.c_str(), data.length());
    if (bytes_written <= 0) {
        int err = SSL_get_error(ssl, bytes_written);
        std::cerr << "SSL write failed: " << err << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

// Function to receive data securely
std::string receive_secure_data(SSL* ssl) {
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl, bytes_read);
        std::cerr << "SSL read failed: " << err << std::endl;
        ERR_print_errors_fp(stderr);
        return "";
    }
    
    buffer[bytes_read] = '\0';
    return std::string(buffer);
}

// Function to close a secure connection
void close_secure_connection(SSL* ssl) {
    if (!ssl) return;
    
    // Get the socket
    int sock = SSL_get_fd(ssl);
    
    // Shutdown the SSL connection
    SSL_shutdown(ssl);
    
    // Free the SSL object
    SSL_free(ssl);
    
    // Close the socket
    if (sock >= 0) close(sock);
}

// Example usage
int main(int argc, char* argv[]) {
    // Default values
    std::string hostname = "example.com";
    int port = 443;
    
    // Parse command line arguments
    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);
    
    // Initialize OpenSSL
    init_openssl();
    
    // Create and configure SSL context
    SSL_CTX* ctx = create_context();
    configure_context(ctx);
    
    // Establish secure connection
    SSL* ssl = establish_secure_connection(ctx, hostname, port);
    if (!ssl) {
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }
    
    // Example: Send HTTP GET request
    std::string request = "GET / HTTP/1.1\r\n"
                          "Host: " + hostname + "\r\n"
                          "Connection: close\r\n\r\n";
    
    if (!send_secure_data(ssl, request)) {
        close_secure_connection(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }
    
    // Receive and display response
    std::string response = receive_secure_data(ssl);
    std::cout << "Response from server:\n" << response.substr(0, 500) << "..." << std::endl;
    
    // Close connection and cleanup
    close_secure_connection(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    
    return 0;
}

