/**
 * Protocol Analyzer Implementation
 * 
 * This example demonstrates protocol analysis:
 * - HTTP protocol parsing
 * - DNS protocol parsing
 * - TLS/SSL protocol identification
 * - Protocol anomaly detection
 * 
 * Requires libpcap development libraries
 * Compile with: g++ protocol_analyzer.cpp -o protocol_analyzer -lpcap
 * 
 * For educational purposes only.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <vector>
#include <map>
#include <algorithm>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <signal.h>
#include <regex>

// Global variables
pcap_t* handle = nullptr;
bool running = true;

// Protocol statistics
struct ProtocolStats {
    int http_requests = 0;
    int http_responses = 0;
    int dns_queries = 0;
    int dns_responses = 0;
    int tls_handshakes = 0;
    int tls_data = 0;
    int anomalies = 0;
};

ProtocolStats stats;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nShutting down protocol analyzer..." << std::endl;
    running = false;
    
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Function to analyze HTTP protocol
void analyze_http(const u_char* payload, int payload_length) {
    // Convert payload to string for easier analysis
    std::string data(reinterpret_cast<const char*>(payload), 
                    std::min(payload_length, 2048));  // Limit to 2KB for analysis
    
    // Check if it's an HTTP request
    std::regex request_regex("^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT) .+ HTTP/\\d\\.\\d");
    if (std::regex_search(data, request_regex)) {
        stats.http_requests++;
        
        std::cout << "HTTP Request detected" << std::endl;
        
        // Extract method, URI, and HTTP version
        std::regex method_uri_regex("^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT) (.+) (HTTP/\\d\\.\\d)");
        std::smatch matches;
        if (std::regex_search(data, matches, method_uri_regex)) {
            std::cout << "   |-Method: " << matches[1] << std::endl;
            std::cout << "   |-URI  {
            std::cout << "   |-Method: " << matches[1] << std::endl;
            std::cout << "   |-URI: " << matches[2] << std::endl;
            std::cout << "   |-Version: " << matches[3] << std::endl;
        }
        
        // Extract Host header
        std::regex host_regex("Host: ([^\\r\\n]+)");
        if (std::regex_search(data, matches, host_regex)) {
            std::cout << "   |-Host: " << matches[1] << std::endl;
        }
        
        // Extract User-Agent header
        std::regex ua_regex("User-Agent: ([^\\r\\n]+)");
        if (std::regex_search(data, matches, ua_regex)) {
            std::cout << "   |-User-Agent: " << matches[1] << std::endl;
        }
        
        // Check for security issues
        if (data.find("Authorization: Basic") != std::string::npos) {
            std::cout << "   |-WARNING: Basic authentication detected (credentials sent in base64)" << std::endl;
        }
        
        if (std::regex_search(data, std::regex("Cookie: ([^\\r\\n]+)"))) {
            std::cout << "   |-INFO: Cookie data present" << std::endl;
        }
    }
    // Check if it's an HTTP response
    else if (std::regex_search(data, std::regex("^HTTP/\\d\\.\\d \\d{3}"))) {
        stats.http_responses++;
        
        std::cout << "HTTP Response detected" << std::endl;
        
        // Extract status code and reason
        std::regex status_regex("^(HTTP/\\d\\.\\d) (\\d{3}) (.+)");
        std::smatch matches;
        if (std::regex_search(data, matches, status_regex)) {
            std::cout << "   |-Version: " << matches[1] << std::endl;
            std::cout << "   |-Status: " << matches[2] << " " << matches[3] << std::endl;
        }
        
        // Extract Content-Type header
        std::regex ct_regex("Content-Type: ([^\\r\\n]+)");
        if (std::regex_search(data, matches, ct_regex)) {
            std::cout << "   |-Content-Type: " << matches[1] << std::endl;
        }
        
        // Check for security headers
        if (data.find("X-XSS-Protection:") == std::string::npos) {
            std::cout << "   |-WARNING: X-XSS-Protection header missing" << std::endl;
        }
        
        if (data.find("X-Content-Type-Options:") == std::string::npos) {
            std::cout << "   |-WARNING: X-Content-Type-Options header missing" << std::endl;
        }
        
        if (data.find("Content-Security-Policy:") == std::string::npos) {
            std::cout << "   |-WARNING: Content-Security-Policy header missing" << std::endl;
        }
    }
    // Check for HTTP anomalies
    else if (data.find("HTTP/") != std::string::npos) {
        stats.anomalies++;
        std::cout << "HTTP Anomaly detected (malformed HTTP message)" << std::endl;
    }
}

// Function to analyze DNS protocol
void analyze_dns(const u_char* payload, int payload_length) {
    // DNS header is at least 12 bytes
    if (payload_length < 12) {
        return;
    }
    
    // Extract DNS header fields
    uint16_t transaction_id = (payload[0] << 8) | payload[1];
    uint16_t flags = (payload[2] << 8) | payload[3];
    uint16_t questions = (payload[4] << 8) | payload[5];
    uint16_t answers = (payload[6] << 8) | payload[7];
    uint16_t authority = (payload[8] << 8) | payload[9];
    uint16_t additional = (payload[10] << 8) | payload[11];
    
    // Check if it's a query or response
    bool is_response = (flags & 0x8000) != 0;
    
    if (is_response) {
        stats.dns_responses++;
        std::cout << "DNS Response detected" << std::endl;
    } else {
        stats.dns_queries++;
        std::cout << "DNS Query detected" << std::endl;
    }
    
    std::cout << "   |-Transaction ID: 0x" << std::hex << transaction_id << std::dec << std::endl;
    std::cout << "   |-Questions: " << questions << std::endl;
    std::cout << "   |-Answers: " << answers << std::endl;
    
    // Extract query name (simplified)
    if (questions > 0 && payload_length > 12) {
        std::string domain;
        int pos = 12;
        
        while (pos < payload_length && payload[pos] != 0) {
            int len = payload[pos++];
            
            // Check for compression pointer
            if ((len & 0xC0) == 0xC0) {
                break;  // Skip compressed names for simplicity
            }
            
            // Add dot if not the first label
            if (!domain.empty()) {
                domain += '.';
            }
            
            // Extract the label
            for (int i = 0; i < len && pos < payload_length; ++i) {
                domain += static_cast<char>(payload[pos++]);
            }
        }
        
        if (!domain.empty()) {
            std::cout << "   |-Query: " << domain << std::endl;
        }
    }
    
    // Check for DNS anomalies
    if (questions > 100 || answers > 100) {
        stats.anomalies++;
        std::cout << "   |-WARNING: Unusually high number of questions or answers" << std::endl;
    }
}

// Function to analyze TLS/SSL protocol
void analyze_tls(const u_char* payload, int payload_length) {
    // TLS record header is at least 5 bytes
    if (payload_length < 5) {
        return;
    }
    
    // Extract TLS record header fields
    uint8_t content_type = payload[0];
    uint16_t version = (payload[1] << 8) | payload[2];
    uint16_t length = (payload[3] << 8) | payload[4];
    
    // Check content type
    std::string content_type_str;
    switch (content_type) {
        case 20: content_type_str = "Change Cipher Spec"; break;
        case 21: content_type_str = "Alert"; break;
        case 22: content_type_str = "Handshake"; break;
        case 23: content_type_str = "Application Data"; break;
        default: content_type_str = "Unknown"; break;
    }
    
    // Check version
    std::string version_str;
    switch (version) {
        case 0x0301: version_str = "TLS 1.0"; break;
        case 0x0302: version_str = "TLS 1.1"; break;
        case 0x0303: version_str = "TLS 1.2"; break;
        case 0x0304: version_str = "TLS 1.3"; break;
        default: version_str = "Unknown"; break;
    }
    
    std::cout << "TLS/SSL Record detected" << std::endl;
    std::cout << "   |-Content Type: " << content_type_str << " (" << static_cast<int>(content_type) << ")" << std::endl;
    std::cout << "   |-Version: " << version_str << " (0x" << std::hex << version << std::dec << ")" << std::endl;
    std::cout << "   |-Length: " << length << " bytes" << std::endl;
    
    // Check for handshake messages
    if (content_type == 22 && payload_length >= 6) {
        uint8_t handshake_type = payload[5];
        std::string handshake_type_str;
        
        switch (handshake_type) {
            case 1: handshake_type_str = "Client Hello"; break;
            case 2: handshake_type_str = "Server Hello"; break;
            case 11: handshake_type_str = "Certificate"; break;
            case 16: handshake_type_str = "Client Key Exchange"; break;
            default: handshake_type_str = "Other"; break;
        }
        
        std::cout << "   |-Handshake Type: " << handshake_type_str << " (" << static_cast<int>(handshake_type) << ")" << std::endl;
        
        stats.tls_handshakes++;
    } else if (content_type == 23) {
        stats.tls_data++;
    }
    
    // Check for TLS anomalies
    if (version < 0x0301) {
        stats.anomalies++;
        std::cout << "   |-WARNING: Obsolete SSL version detected" << std::endl;
    }
}

// Packet processing callback function
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Parse Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    // Parse IP header
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_length = ip_header->ip_hl * 4;
    
    // Process TCP packets
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        int tcp_header_length = tcp_header->th_off * 4;
        
        // Calculate payload offset and size
        int payload_offset = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
        int payload_length = pkthdr->len - payload_offset;
        
        if (payload_length <= 0) {
            return;
        }
        
        const u_char* payload = packet + payload_offset;
        
        // Get source and destination ports
        uint16_t src_port = ntohs(tcp_header->th_sport);
        uint16_t dst_port = ntohs(tcp_header->th_dport);
        
        // Get source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        std::cout << "\n=== Protocol Analysis ===" << std::endl;
        std::cout << "Source: " << src_ip << ":" << src_port << std::endl;
        std::cout << "Destination: " << dst_ip << ":" << dst_port << std::endl;
        std::cout << "Payload Length: " << payload_length << " bytes" << std::endl;
        
        // Analyze based on port numbers
        if (src_port == 80 || dst_port == 80) {
            analyze_http(payload, payload_length);
        } else if (src_port == 53 || dst_port == 53) {
            analyze_dns(payload, payload_length);
        } else if (src_port == 443 || dst_port == 443) {
            analyze_tls(payload, payload_length);
        } else {
            // Try to detect protocol based on content
            if (payload_length >= 4 && 
                (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
                (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')) {
                analyze_http(payload, payload_length);
            } else if (payload_length >= 5 && 
                      (payload[0] >= 20 && payload[0] <= 23) && 
                      (payload[1] == 0x03) && 
                      (payload[2] >= 0x01 && payload[2] <= 0x04)) {
                analyze_tls(payload, payload_length);
            }
        }
    }
    // Process UDP packets
    else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        
        // Calculate payload offset and size
        int payload_offset = sizeof(struct ether_header) + ip_header_length + sizeof(struct udphdr);
        int payload_length = pkthdr->len - payload_offset;
        
        if (payload_length <= 0) {
            return;
        }
        
        const u_char* payload = packet + payload_offset;
        
        // Get source and destination ports
        uint16_t src_port = ntohs(udp_header->uh_sport);
        uint16_t dst_port = ntohs(udp_header->uh_dport);
        
        // Get source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        std::cout << "\n=== Protocol Analysis ===" << std::endl;
        std::cout << "Source: " << src_ip << ":" << src_port << std::endl;
        std::cout << "Destination: " << dst_ip << ":" << dst_port << std::endl;
        std::cout << "Payload Length: " << payload_length << " bytes" << std::endl;
        
        // Analyze based on port numbers
        if (src_port == 53 || dst_port == 53) {
            analyze_dns(payload, payload_length);
        }
    }
}

// Function to print protocol statistics
void print_statistics() {
    std::cout << "\n=== Protocol Statistics ===" << std::endl;
    std::cout << "HTTP Requests: " << stats.http_requests << std::endl;
    std::cout << "HTTP Responses: " << stats.http_responses << std::endl;
    std::cout << "DNS Queries: " << stats.dns_queries << std::endl;
    std::cout << "DNS Responses: " << stats.dns_responses << std::endl;
    std::cout << "TLS Handshakes: " << stats.tls_handshakes << std::endl;
    std::cout << "TLS Data Records: " << stats.tls_data << std::endl;
    std::cout << "Protocol Anomalies: " << stats.anomalies << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Default values
    std::string interface;
    std::string filter_exp = "tcp or udp";
    int num_packets = 0;  // 0 means capture indefinitely
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-f" && i + 1 < argc) {
            filter_exp = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            num_packets = std::stoi(argv[++i]);
        } else if (arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [-i interface] [-f filter] [-c count] [-h]" << std::endl;
            std::cout << "  -i interface   Specify network interface to capture" << std::endl;
            std::cout << "  -f filter      Specify BPF filter expression" << std::endl;
            std::cout << "  -c count       Specify number of packets to capture" << std::endl;
            std::cout << "  -h             Show this help message" << std::endl;
            return 0;
        }
    }
    
    // If no interface specified, prompt user
    if (interface.empty()) {
        std::cout << "Enter interface name: ";
        std::getline(std::cin, interface);
    }
    
    // Error buffer for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open network interface for packet capture
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening interface " << interface << ": " << errbuf << std::endl;
        return 1;
    }
    
    // Set up packet filter
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    
    // Get network address and mask
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << "Warning: Could not get netmask for interface " << interface << std::endl;
        net = 0;
        mask = 0;
    }
    
    // Compile filter expression
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        std::cerr << "Error compiling filter expression: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
    
    // Apply filter
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error applying filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    
    // Free filter program
    pcap_freecode(&fp);
    
    std::cout << "Protocol Analyzer started on interface " << interface << std::endl;
    std::cout << "Filter: " << filter_exp << std::endl;
    std::cout << "Press Ctrl+C to stop capture" << std::endl;
    
    // Start packet capture
    if (num_packets > 0) {
        pcap_loop(handle, num_packets, packet_handler, nullptr);
    } else {
        while (running) {
            pcap_dispatch(handle, -1, packet_handler, nullptr);
        }
    }
    
    // Print statistics
    print_statistics();
    
    // Close pcap handle
    pcap_close(handle);
    
    return 0;
}

