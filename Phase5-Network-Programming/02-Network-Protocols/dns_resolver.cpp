/**
 * DNS Resolver Implementation
 * 
 * This example demonstrates a DNS resolver with:
 * - DNS protocol implementation
 * - Query construction and parsing
 * - Security considerations
 * 
 * For educational purposes only.
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include <iomanip>

// DNS header structure
struct DNSHeader {
    uint16_t id;        // Identification
    uint16_t flags;     // Various flags
    uint16_t qdcount;   // Number of questions
    uint16_t ancount;   // Number of answers
    uint16_t nscount;   // Number of authority records
    uint16_t arcount;   // Number of additional records
};

// DNS question structure
struct DNSQuestion {
    std::string qname;  // Domain name
    uint16_t qtype;     // Query type
    uint16_t qclass;    // Query class
};

// DNS record structure
struct DNSRecord {
    std::string name;   // Domain name
    uint16_t type;      // Record type
    uint16_t rclass;    // Record class
    uint32_t ttl;       // Time to live
    uint16_t rdlength;  // Length of rdata
    std::vector<uint8_t> rdata; // Record data
};

// DNS response structure
struct DNSResponse {
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSRecord> answers;
    std::vector<DNSRecord> authorities;
    std::vector<DNSRecord> additionals;
};

// Function to convert domain name to DNS format
std::vector<uint8_t> domain_to_dns_format(const std::string& domain) {
    std::vector<uint8_t> result;
    
    size_t pos = 0;
    size_t next_pos;
    
    while ((next_pos = domain.find('.', pos)) != std::string::npos) {
        uint8_t len = static_cast<uint8_t>(next_pos - pos);
        result.push_back(len);
        
        for (size_t i = pos; i < next_pos; ++i) {
            result.push_back(static_cast<uint8_t>(domain[i]));
        }
        
        pos = next_pos + 1;
    }
    
    // Add the last part
    uint8_t len = static_cast<uint8_t>(domain.length() - pos);
    result.push_back(len);
    
    for (size_t i = pos; i < domain.length(); ++i) {
        result.push_back(static_cast<uint8_t>(domain[i]));
    }
    
    // Add terminating zero
    result.push_back(0);
    
    return result;
}

// Function to create a DNS query packet
std::vector<uint8_t> create_dns_query(const std::string& domain, uint16_t query_type) {
    std::vector<uint8_t> packet;
    
    // Generate random ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 65535);
    uint16_t id = dis(gen);
    
    // DNS header
    DNSHeader header;
    header.id = htons(id);
    header.flags = htons(0x0100);  // Standard query, recursion desired
    header.qdcount = htons(1);     // One question
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    
    // Add header to packet
    uint8_t* header_ptr = reinterpret_cast<uint8_t*>(&header);
    packet.insert(packet.end(), header_ptr, header_ptr + sizeof(DNSHeader));
    
    // Add question
    std::vector<uint8_t> qname = domain_to_dns_format(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());
    
    // Add query type
    uint16_t qtype = htons(query_type);
    uint8_t* qtype_ptr = reinterpret_cast<uint8_t*>(&qtype);
    packet.insert(packet.end(), qtype_ptr, qtype_ptr + sizeof(uint16_t));
    
    // Add query class (IN)
    uint16_t qclass = htons(1);
    uint8_t* qclass_ptr = reinterpret_cast<uint8_t*>(&qclass);
    packet.insert(packet.end(), qclass_ptr, qclass_ptr + sizeof(uint16_t));
    
    return packet;
}

// Function to extract domain name from DNS packet
std::string extract_name(const std::vector<uint8_t>& packet, size_t& offset) {
    std::string name;
    
    while (true) {
        uint8_t len = packet[offset++];
        
        // Check for compression pointer
        if ((len & 0xC0) == 0xC0) {
            // It's a pointer
            uint16_t pointer = ((len & 0x3F) << 8) | packet[offset++];
            size_t saved_offset = offset;
            offset = pointer;
            name += extract_name(packet, offset);
            offset = saved_offset;
            return name;
        }
        
        // Check for end of name
        if (len == 0) {
            break;
        }
        
        // Add dot if not the first label
        if (!name.empty()) {
            name += '.';
        }
        
        // Extract the label
        for (uint8_t i = 0; i < len; ++i) {
            name += static_cast<char>(packet[offset++]);
        }
    }
    
    return name;
}

// Function to parse DNS response
DNSResponse parse_dns_response(const std::vector<uint8_t>& packet) {
    DNSResponse response;
    size_t offset = 0;
    
    // Parse header
    if (packet.size() < sizeof(DNSHeader)) {
        throw std::runtime_error("Packet too small for DNS header");
    }
    
    memcpy(&response.header, packet.data(), sizeof(DNSHeader));
    response.header.id = ntohs(response.header.id);
    response.header.flags = ntohs(response.header.flags);
    response.header.qdcount = ntohs(response.header.qdcount);
    response.header.ancount = ntohs(response.header.ancount);
    response.header.nscount = ntohs(response.header.nscount);
    response.header.arcount = ntohs(response.header.arcount);
    
    offset = sizeof(DNSHeader);
    
    // Parse questions
    for (uint16_t i = 0; i < response.header.qdcount; ++i) {
        DNSQuestion question;
        question.qname = extract_name(packet, offset);
        
        if (offset + 4 > packet.size()) {
            throw std::runtime_error("Packet too small for question fields");
        }
        
        question.qtype = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        question.qclass = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        response.questions.push_back(question);
    }
    
    // Parse answers
    for (uint16_t i = 0; i < response.header.ancount; ++i) {
        DNSRecord record;
        record.name = extract_name(packet, offset);
        
        if (offset + 10 > packet.size()) {
            throw std::runtime_error("Packet too small for record fields");
        }
        
        record.type = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.rclass = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.ttl = (packet[offset] << 24) | (packet[offset + 1] << 16) | 
                     (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
        
        record.rdlength = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        if (offset + record.rdlength > packet.size()) {
            throw std::runtime_error("Packet too small for record data");
        }
        
        record.rdata.assign(packet.begin() + offset, packet.begin() + offset + record.rdlength);
        offset += record.rdlength;
        
        response.answers.push_back(record);
    }
    
    // Parse authorities (simplified, similar to answers)
    for (uint16_t i = 0; i < response.header.nscount; ++i) {
        DNSRecord record;
        record.name = extract_name(packet, offset);
        
        if (offset + 10 > packet.size()) {
            throw std::runtime_error("Packet too small for authority fields");
        }
        
        record.type = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.rclass = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.ttl = (packet[offset] << 24) | (packet[offset + 1] << 16) | 
                     (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
        
        record.rdlength = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        if (offset + record.rdlength > packet.size()) {
            throw std::runtime_error("Packet too small for authority data");
        }
        
        record.rdata.assign(packet.begin() + offset, packet.begin() + offset + record.rdlength);
        offset += record.rdlength;
        
        response.authorities.push_back(record);
    }
    
    // Parse additionals (simplified, similar to answers)
    for (uint16_t i = 0; i < response.header.arcount; ++i) {
        DNSRecord record;
        record.name = extract_name(packet, offset);
        
        if (offset + 10 > packet.size()) {
            throw std::runtime_error("Packet too small for additional fields");
        }
        
        record.type = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.rclass = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        record.ttl = (packet[offset] << 24) | (packet[offset + 1] << 16) | 
                     (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
        
        record.rdlength = (packet[offset] << 8) | packet[offset + 1];
        offset += 2;
        
        if (offset + record.rdlength > packet.size()) {
            throw std::runtime_error("Packet too small for additional data");
        }
        
        record.rdata.assign(packet.begin() + offset, packet.begin() + offset + record.rdlength);
        offset += record.rdlength;
        
        response.additionals.push_back(record);
    }
    
    return response;
}

// Function to format IP address from record data
std::string format_ip_address(const std::vector<uint8_t>& rdata) {
    if (rdata.size() != 4) {
        return "Invalid IP format";
    }
    
    return std::to_string(rdata[0]) + "." + 
           std::to_string(rdata[1]) + "." + 
           std::to_string(rdata[2]) + "." + 
           std::to_string(rdata[3]);
}

// Function to format IPv6 address from record data
std::string format_ipv6_address(const std::vector<uint8_t>& rdata) {
    if (rdata.size() != 16) {
        return "Invalid IPv6 format";
    }
    
    std::stringstream ss;
    ss << std::hex;
    
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) {
            ss << ":";
        }
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(rdata[i]) << 
              std::setw(2) << std::setfill('0') << static_cast<int>(rdata[i+1]);
    }
    
    return ss.str();
}

// Function to print record data based on type
std::string format_record_data(const DNSRecord& record) {
    switch (record.type) {
        case 1:  // A record
            return format_ip_address(record.rdata);
        case 2:  // NS record
            {
                size_t offset = 0;
                return extract_name(record.rdata, offset);
            }
        case 5:  // CNAME record
            {
                size_t offset = 0;
                return extract_name(record.rdata, offset);
            }
        case 15: // MX record
            {
                uint16_t preference = (record.rdata[0] << 8) | record.rdata[1];
                size_t offset = 2;
                std::string exchange = extract_name(record.rdata, offset);
                return "Preference: " + std::to_string(preference) + ", Exchange: " + exchange;
            }
        case 28: // AAAA record
            return format_ipv6_address(record.rdata);
        default:
            return "Data length: " + std::to_string(record.rdlength) + " bytes";
    }
}

// Function to get record type name
std::string get_record_type_name(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 257: return "CAA";
        default: return "TYPE" + std::to_string(type);
    }
}

// Main function
int main(int argc, char* argv[]) {
    // Default values
    std::string domain = "example.com";
    std::string dns_server = "8.8.8.8";
    uint16_t query_type = 1;  // A record
    
    // Parse command line arguments
    if (argc > 1) {
        domain = argv[1];
    }
    
    if (argc > 2) {
        dns_server = argv[2];
    }
    
    if (argc > 3) {
        if (std::string(argv[3]) == "A") {
            query_type = 1;
        } else if (std::string(argv[3]) == "NS") {
            query_type = 2;
        } else if (std::string(argv[3]) == "CNAME") {
            query_type = 5;
        } else if (std::string(argv[3]) == "MX") {
            query_type = 15;
        } else if (std::string(argv[3]) == "AAAA") {
            query_type = 28;
        } else {
            try {
                query_type = std::stoi(argv[3]);
            } catch (...) {
                std::cerr << "Invalid query type: " << argv[3] << std::endl;
                return 1;
            }
        }
    }
    
    std::cout << "Resolving " << domain << " using DNS server " << dns_server 
              << " (Type: " << get_record_type_name(query_type) << ")" << std::endl;
    
    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        std::cerr << "Failed to set receive timeout: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }
    
    // Set up DNS server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);  // DNS port
    
    if (inet_pton(AF_INET, dns_server.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid DNS server address: " << dns_server << std::endl;
        close(sock);
        return 1;
    }
    
    // Create DNS query
    std::vector<uint8_t> query = create_dns_query(domain, query_type);
    
    // Send query
    if (sendto(sock, query.data(), query.size(), 0, 
              (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send DNS query: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }
    
    // Receive response
    uint8_t response_buffer[1024];
    socklen_t server_len = sizeof(server_addr);
    
    ssize_t bytes_received = recvfrom(sock, response_buffer, sizeof(response_buffer), 0,
                                     (struct sockaddr*)&server_addr, &server_len);
    
    if (bytes_received < 0) {
        std::cerr << "Failed to receive DNS response: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }
    
    // Close socket
    close(sock);
    
    // Parse response
    std::vector<uint8_t> response_packet(response_buffer, response_buffer + bytes_received);
    
    try {
        DNSResponse response = parse_dns_response(response_packet);
        
        // Print response details
        std::cout << "\nResponse contains:" << std::endl;
        std::cout << "  Questions: " << response.questions.size() << std::endl;
        std::cout << "  Answers: " << response.answers.size() << std::endl;
        std::cout << "  Authority records: " << response.authorities.size() << std::endl;
        std::cout << "  Additional records: " << response.additionals.size() << std::endl;
        
        // Print answers
        if (!response.answers.empty()) {
            std::cout << "\nAnswers:" << std::endl;
            for (const auto& record : response.answers) {
                std::cout << "  " << record.name << " "
                          << get_record_type_name(record.type) << " "
                          << format_record_data(record) << " (TTL: " << record.ttl << "s)" << std::endl;
            }
        }
        
        // Print authority records
        if (!response.authorities.empty()) {
            std::cout << "\nAuthority Records:" << std::endl;
            for (const auto& record : response.authorities) {
                std::cout << "  " << record.name << " "
                          << get_record_type_name(record.type) << " "
                          << format_record_data(record) << " (TTL: " << record.ttl << "s)" << std::endl;
            }
        }
        
        // Print additional records
        if (!response.additionals.empty()) {
            std::cout << "\nAdditional Records:" << std::endl;
            for (const auto& record : response.additionals) {
                std::cout << "  " << record.name << " "
                          << get_record_type_name(record.type) << " "
                          << format_record_data(record) << " (TTL: " << record.ttl << "s)" << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error parsing DNS response: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

