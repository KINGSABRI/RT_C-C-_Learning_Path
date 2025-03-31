/**
 * Packet Capture and Analysis using libpcap
 * 
 * This example demonstrates packet capture using libpcap:
 * - Interface selection
 * - Packet filtering with BPF
 * - Protocol analysis
 * - Traffic statistics
 * 
 * Requires libpcap development libraries
 * Compile with: g++ pcap_analyzer.cpp -o pcap_analyzer -lpcap
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

// Global variables
pcap_t* handle = nullptr;
bool running = true;
std::map<std::string, int> ip_counts;
std::map<uint16_t, int> port_counts;
std::map<uint8_t, int> protocol_counts;
int total_packets = 0;
int total_bytes = 0;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nShutting down packet capture..." << std::endl;
    running = false;
    
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Function to print MAC address
std::string mac_to_string(const uint8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

// Function to get protocol name
std::string get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default: return "Other (" + std::to_string(protocol) + ")";
    }
}

// Function to get service name for common ports
std::string get_service_name(uint16_t port) {
    switch (port) {
        case 20: return "FTP-Data";
        case 21: return "FTP-Control";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3389: return "RDP";
        default: return std::to_string(port);
    }
}

// Packet processing callback function
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Update statistics
    total_packets++;
    total_bytes += pkthdr->len;
    
    // Parse Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    // Parse IP header
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_length = ip_header->ip_hl * 4;
    
    // Update IP statistics
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    
    ip_counts[src_ip]++;
    ip_counts[dst_ip]++;
    
    // Update protocol statistics
    protocol_counts[ip_header->ip_p]++;
    
    // Parse TCP/UDP headers and update port statistics
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        port_counts[ntohs(tcp_header->th_sport)]++;
        port_counts[ntohs(tcp_header->th_dport)]++;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        port_counts[ntohs(udp_header->uh_sport)]++;
        port_counts[ntohs(udp_header->uh_dport)]++;
    }
    
    // Print packet summary
    std::cout << "Packet #" << total_packets << ": " << pkthdr->len << " bytes, "
              << src_ip << " -> " << dst_ip << ", "
              << get_protocol_name(ip_header->ip_p);
    
    // Print port information for TCP/UDP
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        std::cout << ", Port " << ntohs(tcp_header->th_sport) << " -> " << ntohs(tcp_header->th_dport);
        
        // Print TCP flags
        std::cout << " [";
        if (tcp_header->th_flags & TH_FIN) std::cout << "FIN ";
        if (tcp_header->th_flags & TH_SYN) std::cout << "SYN ";
        if (tcp_header->th_flags & TH_RST) std::cout << "RST ";
        if (tcp_header->th_flags & TH_PUSH) std::cout << "PSH ";
        if (tcp_header->th_flags & TH_ACK) std::cout << "ACK ";
        if (tcp_header->th_flags & TH_URG) std::cout << "URG ";
        std::cout << "]";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_length);
        std::cout << ", Port " << ntohs(udp_header->uh_sport) << " -> " << ntohs(udp_header->uh_dport);
    }
    
    std::cout << std::endl;
}

// Function to print network interfaces
void print_interfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Get all network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding network interfaces: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "Available Network Interfaces:" << std::endl;
    
    // Print interface details
    int i = 1;
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next, ++i) {
        std::cout << i << ". " << dev->name;
        if (dev->description) {
            std::cout << " (" << dev->description << ")";
        }
        std::cout << std::endl;
        
        // Print addresses
        for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr) {
                if (addr->addr->sa_family == AF_INET) {
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr->addr;
                    std::cout << "    IPv4: " << inet_ntoa(ipv4->sin_addr);
                    
                    if (addr->netmask) {
                        struct sockaddr_in* mask = (struct sockaddr_in*)addr->netmask;
                        std::cout << ", Netmask: " << inet_ntoa(mask->sin_addr);
                    }
                    
                    std::cout << std::endl;
                }
            }
        }
    }
    
    // Free the interface list
    pcap_freealldevs(alldevs);
}

// Function to print statistics
void print_statistics() {
    std::cout << "\n=== Capture Statistics ===" << std::endl;
    std::cout << "Total Packets: " << total_packets << std::endl;
    std::cout << "Total Bytes: " << total_bytes << std::endl;
    
    // Print top IP addresses
    std::cout << "\nTop IP Addresses:" << std::endl;
    std::vector<std::pair<std::string, int>> ip_vec(ip_counts.begin(), ip_counts.end());
    std::sort(ip_vec.begin(), ip_vec.end(), 
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(ip_vec.size(), size_t(10)); ++i) {
        std::cout << std::setw(15) << ip_vec[i].first << ": " 
                  << ip_vec[i].second << " packets" << std::endl;
    }
    
    // Print top protocols
    std::cout << "\nProtocol Distribution:" << std::endl;
    std::vector<std::pair<uint8_t, int>> proto_vec(protocol_counts.begin(), protocol_counts.end());
    std::sort(proto_vec.begin(), proto_vec.end(), 
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& proto : proto_vec) {
        std::cout << std::setw(10) << get_protocol_name(proto.first) << ": " 
                  << proto.second << " packets" << std::endl;
    }
    
    // Print top ports
    std::cout << "\nTop Ports:" << std::endl;
    std::vector<std::pair<uint16_t, int>> port_vec(port_counts.begin(), port_counts.end());
    std::sort(port_vec.begin(), port_vec.end(), 
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(port_vec.size(), size_t(10)); ++i) {
        std::cout << std::setw(5) << port_vec[i].first << " (" 
                  << std::setw(10) << get_service_name(port_vec[i].first) << "): " 
                  << port_vec[i].second << " packets" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Default values
    std::string interface;
    std::string filter_exp;
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
        } else if (arg == "-l") {
            print_interfaces();
            return 0;
        } else if (arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [-i interface] [-f filter] [-c count] [-l] [-h]" << std::endl;
            std::cout << "  -i interface   Specify network interface to capture" << std::endl;
            std::cout << "  -f filter      Specify BPF filter expression" << std::endl;
            std::cout << "  -c count       Specify number of packets to capture" << std::endl;
            std::cout << "  -l             List available network interfaces" << std::endl;
            std::cout << "  -h             Show this help message" << std::endl;
            return 0;
        }
    }
    
    // If no interface specified, list available interfaces and prompt user
    if (interface.empty()) {
        print_interfaces();
        std::cout << "\nEnter interface name: ";
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
    
    // Check if it's an Ethernet interface
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Interface " << interface << " is not an Ethernet interface" << std::endl;
        pcap_close(handle);
        return 1;
    }
    
    // Set up packet filter if specified
    if (!filter_exp.empty()) {
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
    }
    
    std::cout << "Starting packet capture on interface " << interface << std::endl;
    if (!filter_exp.empty()) {
        std::cout << "Filter: " << filter_exp << std::endl;
    }
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

