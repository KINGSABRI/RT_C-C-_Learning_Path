#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>

/**
 * Simple Network Packet Analyzer
 * 
 * This is a simplified version of the packet analyzer that demonstrates
 * the core concepts without the full implementation complexity.
 */

// Utility functions for packet analysis
namespace PacketUtils {
    // Convert a byte array to a hexadecimal string
    std::string bytesToHex(const uint8_t* data, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < length; ++i) {
            ss << std::setw(2) << static_cast<int>(data[i]);
            if (i < length - 1) {
                ss << " ";
            }
        }
        
        return ss.str();
    }
    
    // Convert a MAC address to a string
    std::string macToString(const uint8_t* mac) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (int i = 0; i < 6; ++i) {
            ss << std::setw(2) << static_cast<int>(mac[i]);
            if (i < 5) {
                ss << ":";
            }
        }
        
        return ss.str();
    }
    
    // Convert an IP address to a string
    std::string ipToString(uint32_t ip) {
        std::stringstream ss;
        ss << ((ip >> 24) & 0xFF) << "."
           << ((ip >> 16) & 0xFF) << "."
           << ((ip >> 8) & 0xFF) << "."
           << (ip & 0xFF);
        
        return ss.str();
    }
    
    // Get protocol name from protocol number
    std::string getProtocolName(uint8_t protocol) {
        switch (protocol) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            default: return "Unknown (" + std::to_string(protocol) + ")";
        }
    }
    
    // Get well-known port name
    std::string getPortName(uint16_t port) {
        switch (port) {
            case 20: return "FTP Data";
            case 21: return "FTP Control";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 67: return "DHCP Server";
            case 68: return "DHCP Client";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 3389: return "RDP";
            default: return std::to_string(port);
        }
    }
}

// Ethernet header class
class EthernetHeader {
private:
    uint8_t destMAC[6];    // Destination MAC address
    uint8_t sourceMAC[6];  // Source MAC address
    uint16_t etherType;    // EtherType (e.g., 0x0800 for IPv4)
    
public:
    // Constructor
    EthernetHeader() {
        memset(destMAC, 0, sizeof(destMAC));
        memset(sourceMAC, 0, sizeof(sourceMAC));
        etherType = 0;
    }
    
    // Parse Ethernet header from raw data
    bool parse(const uint8_t* data, size_t length) {
        // Check if we have enough data for an Ethernet header
        if (length < 14) {
            std::cerr << "Error: Not enough data for Ethernet header" << std::endl;
            return false;
        }
        
        // Copy destination MAC
        memcpy(destMAC, data, 6);
        
        // Copy source MAC
        memcpy(sourceMAC, data + 6, 6);
        
        // Get EtherType (in network byte order)
        etherType = (data[12] << 8) | data[13];
        
        return true;
    }
    
    // Getters
    const uint8_t* getDestMAC() const { return destMAC; }
    const uint8_t* getSourceMAC() const { return sourceMAC; }
    uint16_t getEtherType() const { return etherType; }
    
    // Get destination MAC as string
    std::string getDestMACString() const {
        return PacketUtils::macToString(destMAC);
    }
    
    // Get source MAC as string
    std::string getSourceMACString() const {
        return PacketUtils::macToString(sourceMAC);
    }
    
    // Get EtherType as string
    std::string getEtherTypeString() const {
        switch (etherType) {
            case 0x0800: return "IPv4";
            case 0x0806: return "ARP";
            case 0x86DD: return "IPv6";
            default: {
                std::stringstream ss;
                ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << etherType;
                return ss.str();
            }
        }
    }
    
    // Print Ethernet header information
    void print() const {
        std::cout << "Ethernet Header:" << std::endl;
        std::cout << "  Destination MAC: " << getDestMACString() << std::endl;
        std::cout << "  Source MAC: " << getSourceMACString() << std::endl;
        std::cout << "  EtherType: " << getEtherTypeString() << std::endl;
    }
    
    // Get header size
    static size_t getHeaderSize() {
        return 14;  // 6 + 6 + 2 bytes
    }
};

// IPv4 header class
class IPv4Header {
private:
    uint8_t version;         // IP version (4 for IPv4)
    uint8_t headerLength;    // Header length in 32-bit words
    uint8_t dscp;            // Differentiated Services Code Point
    uint8_t ecn;             // Explicit Congestion Notification
    uint16_t totalLength;    // Total length of the packet
    uint16_t identification; // Identification field
    bool dontFragment;       // Don't Fragment flag
    bool moreFragments;      // More Fragments flag
    uint16_t fragmentOffset; // Fragment offset
    uint8_t ttl;             // Time to Live
    uint8_t protocol;        // Protocol (e.g., 6 for TCP)
    uint16_t checksum;       // Header checksum
    uint32_t sourceIP;       // Source IP address
    uint32_t destIP;         // Destination IP address
    
public:
    // Constructor
    IPv4Header() {
        version = 0;
        headerLength = 0;
        dscp = 0;
        ecn = 0;
        totalLength = 0;
        identification = 0;
        dontFragment = false;
        moreFragments = false;
        fragmentOffset = 0;
        ttl = 0;
        protocol = 0;
        checksum = 0;
        sourceIP = 0;
        destIP = 0;
    }
    
    // Parse IPv4 header from raw data
    bool parse(const uint8_t* data, size_t length) {
        // Check if we have enough data for an IPv4 header
        if (length < 20) {
            std::cerr << "Error: Not enough data for IPv4 header" << std::endl;
            return false;
        }
        
        // Get version and header length
        version = (data[0] >> 4) & 0x0F;
        headerLength = (data[0] & 0x0F) * 4;  // Convert to bytes
        
        // Check version
        if (version != 4) {
            std::cerr << "Error: Not an IPv4 packet (version = " << static_cast<int>(version) << ")" << std::endl;
            return false;
        }
        
        // Check header length
        if (headerLength < 20 || headerLength > length) {
            std::cerr << "Error: Invalid IPv4 header length (" << static_cast<int>(headerLength) << " bytes)" << std::endl;
            return false;
        }
        
        // Get DSCP and ECN
        dscp = (data[1] >> 2) & 0x3F;
        ecn = data[1] & 0x03;
        
        // Get total length
        totalLength = (data[2] << 8) | data[3];
        
        // Get identification
        identification = (data[4] << 8) | data[5];
        
        // Get flags and fragment offset
        uint16_t flagsAndOffset = (data[6] << 8) | data[7];
        dontFragment = (flagsAndOffset & 0x4000) != 0;
        moreFragments = (flagsAndOffset & 0x2000) != 0;
        fragmentOffset = flagsAndOffset & 0x1FFF;
        
        // Get TTL
        ttl = data[8];
        
        // Get protocol
        protocol = data[9];
        
        // Get checksum
        checksum = (data[10] << 8) | data[11];
        
        // Get source IP
        sourceIP = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
        
        // Get destination IP
        destIP = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
        
        return true;
    }
    
    // Getters
    uint8_t getVersion() const { return version; }
    uint8_t getHeaderLength() const { return headerLength; }
    uint8_t getDSCP() const { return dscp; }
    uint8_t getECN() const { return ecn; }
    uint16_t getTotalLength() const { return totalLength; }
    uint16_t getIdentification() const { return identification; }
    bool getDontFragment() const { return dontFragment; }
    bool getMoreFragments() const { return moreFragments; }
    uint16_t getFragmentOffset() const { return fragmentOffset; }
    uint8_t getTTL() const { return ttl; }
    uint8_t getProtocol() const { return protocol; }
    uint16_t getChecksum() const { return checksum; }
    uint32_t getSourceIP() const { return sourceIP; }
    uint32_t getDestIP() const { return destIP; }
    
    // Get source IP as string
    std::string getSourceIPString() const {
        return PacketUtils::ipToString(sourceIP);
    }
    
    // Get destination IP as string
    std::string getDestIPString() const {
        return PacketUtils::ipToString(destIP);
    }
    
    // Get protocol as string
    std::string getProtocolString() const {
        return PacketUtils::getProtocolName(protocol);
    }
    
    // Print IPv4 header information
    void print() const {
        std::cout << "IPv4 Header:" << std::endl;
        std::cout << "  Version: " << static_cast<int>(version) << std::endl;
        std::cout << "  Header Length: " << static_cast<int>(headerLength) << " bytes" << std::endl;
        std::cout << "  DSCP: " << static_cast<int>(dscp) << std::endl;
        std::cout << "  ECN: " << static_cast<int>(ecn) << std::endl;
        std::cout << "  Total Length: " << totalLength << " bytes" << std::endl;
        std::cout << "  Identification: 0x" << std::hex << std::setw(4) << std::setfill('0') 
                  << identification << std::dec << std::endl;
        std::cout << "  Flags: " 
                  << (dontFragment ? "DF " : "") 
                  << (moreFragments ? "MF" : "") 
                  << ((!dontFragment && !moreFragments) ? "None" : "") 
                  << std::endl;
        std::cout << "  Fragment Offset: " << fragmentOffset << std::endl;
        std::cout << "  TTL: " << static_cast<int>(ttl) << std::endl;
        std::cout << "  Protocol: " << getProtocolString() << " (" << static_cast<int>(protocol) << ")" << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << std::setw(4) << std::setfill('0') 
                  << checksum << std::dec << std::endl;
        std::cout << "  Source IP: " << getSourceIPString() << std::endl;
        std::cout << "  Destination IP: " << getDestIPString() << std::endl;
    }
};

// TCP header class
class TCPHeader {
private:
    uint16_t sourcePort;     // Source port
    uint16_t destPort;       // Destination port
    uint32_t sequenceNumber; // Sequence number
    uint32_t ackNumber;      // Acknowledgment number
    uint8_t dataOffset;      // Data offset in 32-bit words
    uint8_t flags;           // TCP flags
    uint16_t window;         // Window size
    uint16_t checksum;       // Checksum
    uint16_t urgentPointer;  // Urgent pointer
    
public:
    // Constructor
    TCPHeader() {
        sourcePort = 0;
        destPort = 0;
        sequenceNumber = 0;
        ackNumber = 0;
        dataOffset = 0;
        flags = 0;
        window = 0;
        checksum = 0;
        urgentPointer = 0;
    }
    
    // Parse TCP header from raw data
    bool parse(const uint8_t* data, size_t length) {
        // Check if we have enough data for a TCP header
        if (length < 20) {
            std::cerr << "Error: Not enough data for TCP header" << std::endl;
            return false;
        }
        
        // Get source port
        sourcePort = (data[0] << 8) | data[1];
        
        // Get destination port
        destPort = (data[2] << 8) | data[3];
        
        // Get sequence number
        sequenceNumber = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        
        // Get acknowledgment number
        ackNumber = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
        
        // Get data offset and reserved bits
        dataOffset = (data[12] >> 4) & 0x0F;
        
        // Get flags
        flags = data[13];
        
        // Get window size
        window = (data[14] << 8) | data[15];
        
        // Get checksum
        checksum = (data[16] << 8) | data[17];
        
        // Get urgent pointer
        urgentPointer = (data[18] << 8) | data[19];
        
        return true;
    }
    
    // Getters
    uint16_t getSourcePort() const { return sourcePort; }
    uint16_t getDestPort() const { return destPort; }
    uint32_t getSequenceNumber() const { return sequenceNumber; }
    uint32_t getAckNumber() const { return ackNumber; }
    uint8_t getDataOffset() const { return dataOffset * 4; }
    uint8_t getFlags() const { return flags; }
    uint16_t getWindow() const { return window; }
    uint16_t getChecksum() const { return checksum; }
    uint16_t getUrgentPointer() const { return urgentPointer; }
    
    // Get source port as string
    std::string getSourcePortString() const {
        return PacketUtils::getPortName(sourcePort);
    }
    
    // Get destination port as string
    std::string getDestPortString() const {
        return PacketUtils::getPortName(destPort);
    }
    
    // Get flags as string
    std::string getFlagsString() const {
        std::string result;
        
        if (flags & 0x01) result += "FIN ";
        if (flags & 0x02) result += "SYN ";
        if (flags & 0x04) result += "RST ";
        if (flags & 0x08) result += "PSH ";
        if (flags & 0x10) result += "ACK ";
        if (flags & 0x20) result += "URG ";
        
        if (result.empty()) {
            return "None";
        } else {
            // Remove trailing space
            return result.substr(0, result.length() - 1);
        }
    }
    
    // Print TCP header information
    void print() const {
        std::cout << "TCP Header:" << std::endl;
        std::cout << "  Source Port: " << sourcePort << " (" << getSourcePortString() << ")" << std::endl;
        std::cout << "  Destination Port: " << destPort << " (" << getDestPortString() << ")" << std::endl;
        std::cout << "  Sequence Number: " << sequenceNumber << std::endl;
        std::cout << "  Acknowledgment Number: " << ackNumber << std::endl;
        std::cout << "  Header Length: " << static_cast<int>(getDataOffset()) << " bytes" << std::endl;
        std::cout << "  Flags: " << getFlagsString() << std::endl;
        std::cout << "  Window Size: " << window << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << std::setw(4) << std::setfill('0') 
                  << checksum << std::dec << std::endl;
        std::cout << "  Urgent Pointer: " << urgentPointer << std::endl;
    }
};

// Simple packet class
class Packet {
private:
    std::vector<uint8_t> rawData;
    EthernetHeader ethernetHeader;
    IPv4Header ipv4Header;
    TCPHeader tcpHeader;
    bool hasEthernet;
    bool hasIPv4;
    bool hasTCP;
    
public:
    // Constructor
    Packet() : hasEthernet(false), hasIPv4(false), hasTCP(false) {
    }
    
    // Set raw packet data
    void setData(const uint8_t* data, size_t length) {
        rawData.assign(data, data + length);
        parse();
    }
    
    // Parse the packet
    void parse() {
        if (rawData.size() < 14) {
            return;  // Not enough data for an Ethernet header
        }
        
        // Parse Ethernet header
        hasEthernet = ethernetHeader.parse(rawData.data(), rawData.size());
        
        // If we have an IPv4 packet, parse the IPv4 header
        if (hasEthernet && ethernetHeader.getEtherType() == 0x0800) {
            const uint8_t* ipData = rawData.data() + EthernetHeader::getHeaderSize();
            size_t ipDataLength = rawData.size() - EthernetHeader::getHeaderSize();
            
            hasIPv4 = ipv4Header.parse(ipData, ipDataLength);
            
            // If we have a TCP packet, parse the TCP header
            if (hasIPv4 && ipv4Header.getProtocol() == 6) {
                const uint8_t* tcpData = ipData + ipv4Header.getHeaderLength();
                size_t tcpDataLength = ipDataLength - ipv4Header.getHeaderLength();
                
                hasTCP = tcpHeader.parse(tcpData, tcpDataLength);
            }
        }
    }
    
    // Print packet information
    void print() const {
        std::cout << "=== Packet Analysis ===\n" << std::endl;
        
        if (hasEthernet) {
            ethernetHeader.print();
            std::cout << std::endl;
            
            if (hasIPv4) {
                ipv4Header.print();
                std::cout << std::endl;
                
                if (hasTCP) {
                    tcpHeader.print();
                    std::cout << std::endl;
                }
            }
        }
        
        std::cout << "Raw packet data (" << rawData.size() << " bytes):" << std::endl;
        std::cout << PacketUtils::bytesToHex(rawData.data(), std::min(rawData.size(), size_t(64))) << std::endl;
        if (rawData.size() > 64) {
            std::cout << "... (truncated)" << std::endl;
        }
    }
    
    // Check if the packet has an Ethernet header
    bool hasEthernetHeader() const { return hasEthernet; }
    
    // Check if the packet has an IPv4 header
    bool hasIPv4Header() const { return hasIPv4; }
    
    // Check if the packet has a TCP header
    bool hasTCPHeader() const { return hasTCP; }
    
    // Get the Ethernet header
    const EthernetHeader& getEthernetHeader() const { return ethernetHeader; }
    
    // Get the IPv4 header
    const IPv4Header& getIPv4Header() const { return ipv4Header; }
    
    // Get the TCP header
    const TCPHeader& getTCPHeader() const { return tcpHeader; }
};

// Create a sample packet for demonstration
void createSamplePacket(Packet& packet) {
    // Sample packet data (Ethernet + IPv4 + TCP)
    uint8_t sampleData[] = {
        // Ethernet header
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,  // Destination MAC
        0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x00,  // Source MAC
        0x08, 0x00,                          // EtherType (IPv4)
        
        // IPv4 header
        0x45, 0x00,                          // Version, IHL, DSCP, ECN
        0x00, 0x3C,                          // Total Length
        0xAB, 0xCD,                          // Identification
        0x40, 0x00,                          // Flags, Fragment Offset
        0x40, 0x06,                          // TTL, Protocol (TCP)
        0x00, 0x00,                          // Header Checksum
        0xC0, 0xA8, 0x01, 0x01,              // Source IP (192.168.1.1)
        0xC0, 0xA8, 0x01, 0x02,              // Destination IP (192.168.1.2)
        
        // TCP header
        0x00, 0x50,                          // Source Port (80)
        0xC0, 0x0C,                          // Destination Port (49164)
        0x00, 0x00, 0x00, 0x01,              // Sequence Number
        0x00, 0x00, 0x00, 0x00,              // Acknowledgment Number
        0x50, 0x12,                          // Data Offset, Flags (SYN, ACK)
        0x72, 0x10,                          // Window Size
        0x00, 0x00,                          // Checksum
        0x00, 0x00,                          // Urgent Pointer
        
        // Payload (sample HTTP data)
        0x48, 0x54, 0x54, 0x50, 0x2F, 0x31,  // "HTTP/1"
        0x2E, 0x31, 0x20, 0x32, 0x30, 0x30,  // ".1 200"
        0x20, 0x4F, 0x4B                     // " OK"
    };
    
    // Set the packet data
    packet.setData(sampleData, sizeof(sampleData));
}

int main() {
    std::cout << "=== Simple Network Packet Analyzer ===\n\n";
    
    // Create a packet
    Packet packet;
    
    // Create a sample packet
    createSamplePacket(packet);
    
    // Analyze the packet
    packet.print();
    
    std::cout << "\n=== Security Analysis ===\n" << std::endl;
    
    // Perform some basic security analysis
    if (packet.hasIPv4Header()) {
        const IPv4Header& ipHeader = packet.getIPv4Header();
        
        // Check for private IP addresses
        std::string sourceIP = ipHeader.getSourceIPString();
        std::string destIP = ipHeader.getDestIPString();
        
        bool sourceIsPrivate = sourceIP.find("192.168.") == 0 || 
                              sourceIP.find("10.") == 0 || 
                              sourceIP.find("172.16.") == 0;
        
        bool destIsPrivate = destIP.find("192.168.") == 0 || 
                            destIP.find("10.") == 0 || 
                            destIP.find("172.16.") == 0;
        
        std::cout << "Source IP (" << sourceIP << ") is " 
                  << (sourceIsPrivate ? "private" : "public") << std::endl;
        
        std::cout << "Destination IP (" << destIP << ") is " 
                  << (destIsPrivate ? "private" : "public") << std::endl;
        
        // Check for suspicious ports
        if (packet.hasTCPHeader()) {
            const TCPHeader& tcpHeader = packet.getTCPHeader();
            
            uint16_t sourcePort = tcpHeader.getSourcePort();
            uint16_t destPort = tcpHeader.getDestPort();
            
            std::cout << "Source Port: " << sourcePort << " (" 
                      << tcpHeader.getSourcePortString() << ")" << std::endl;
            
            std::cout << "Destination Port: " << destPort << " (" 
                      << tcpHeader.getDestPortString() << ")" << std::endl;
            
            // Check for common service ports
            if (sourcePort == 80 || destPort == 80) {
                std::cout << "HTTP traffic detected" << std::endl;
            } else if (sourcePort == 443 || destPort == 443) {
                std::cout << "HTTPS traffic detected" << std::endl;
            } else if (sourcePort == 22 || destPort == 22) {
                std::cout << "SSH traffic detected" << std::endl;
            } else if (sourcePort == 23 || destPort == 23) {
                std::cout << "WARNING: Telnet traffic detected (insecure protocol)" << std::endl;
            }
            
            // Check for suspicious flags
            std::string flags = tcpHeader.getFlagsString();
            std::cout << "TCP Flags: " << flags << std::endl;
            
            if (flags.find("SYN") != std::string::npos && flags.find("FIN") != std::string::npos) {
                std::cout << "WARNING: Suspicious flag combination (SYN+FIN)" << std::endl;
            }
        }
    }
    
    std::cout << "\n=== End of Packet Analysis ===\n";
    
    return 0;
}

