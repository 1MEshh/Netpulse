#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <array>
#include <optional>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>

namespace netpulse {

// Hardware MAC Address (6 octets)
struct MacAddress {
    std::array<uint8_t, 6> octets{};

    constexpr MacAddress() = default;
    constexpr explicit MacAddress(const std::array<uint8_t, 6>& bytes) : octets(bytes) {}
    constexpr MacAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5)
        : octets{b0, b1, b2, b3, b4, b5} {}

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        for (size_t i = 0; i < octets.size(); ++i) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(octets[i]);
        }
        return oss.str();
    }

    [[nodiscard]] std::string oui_prefix() const {
        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(octets[0]) << ":"
            << std::setw(2) << std::setfill('0') << static_cast<int>(octets[1]) << ":"
            << std::setw(2) << std::setfill('0') << static_cast<int>(octets[2]);
        return oss.str();
    }

    [[nodiscard]] bool is_broadcast() const {
        return std::all_of(octets.begin(), octets.end(), [](uint8_t b) { return b == 0xFF; });
    }

    [[nodiscard]] bool is_multicast() const {
        return (octets[0] & 0x01) != 0;
    }

    [[nodiscard]] bool is_zero() const {
        return std::all_of(octets.begin(), octets.end(), [](uint8_t b) { return b == 0x00; });
    }

    bool operator==(const MacAddress& other) const = default;
    auto operator<=>(const MacAddress& other) const = default;

    static std::optional<MacAddress> parse(std::string_view str) {
        if (str.size() < 17) return std::nullopt;
        MacAddress addr{};
        size_t idx = 0;
        uint8_t cur = 0;
        int digit_count = 0;

        for (char ch : str) {
            if (ch == ':' || ch == '-') {
                if (digit_count == 0 || idx >= 6) return std::nullopt;
                addr.octets[idx++] = cur;
                cur = 0;
                digit_count = 0;
                continue;
            }
            int val = -1;
            if (ch >= '0' && ch <= '9') val = ch - '0';
            else if (ch >= 'a' && ch <= 'f') val = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') val = ch - 'A' + 10;
            else return std::nullopt;

            cur = static_cast<uint8_t>((cur << 4) | val);
            digit_count++;
            if (digit_count > 2) return std::nullopt;
        }

        if (digit_count > 0 && idx < 6) {
            addr.octets[idx++] = cur;
        }
        if (idx != 6) return std::nullopt;
        return addr;
    }
};

// IPv4 Address (4 octets)
struct Ipv4Address {
    std::array<uint8_t, 4> octets{};

    constexpr Ipv4Address() = default;
    constexpr explicit Ipv4Address(const std::array<uint8_t, 4>& bytes) : octets(bytes) {}
    constexpr Ipv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : octets{a, b, c, d} {}

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << static_cast<int>(octets[0]) << "."
            << static_cast<int>(octets[1]) << "."
            << static_cast<int>(octets[2]) << "."
            << static_cast<int>(octets[3]);
        return oss.str();
    }

    [[nodiscard]] uint32_t to_u32() const {
        return (static_cast<uint32_t>(octets[0]) << 24) |
               (static_cast<uint32_t>(octets[1]) << 16) |
               (static_cast<uint32_t>(octets[2]) << 8) |
               static_cast<uint32_t>(octets[3]);
    }

    [[nodiscard]] bool is_zero() const {
        return std::all_of(octets.begin(), octets.end(), [](uint8_t b) { return b == 0; });
    }

    [[nodiscard]] bool is_broadcast() const {
        return std::all_of(octets.begin(), octets.end(), [](uint8_t b) { return b == 0xFF; });
    }

    bool operator==(const Ipv4Address& other) const = default;
    auto operator<=>(const Ipv4Address& other) const = default;

    static std::optional<Ipv4Address> parse(std::string_view str) {
        std::array<uint8_t, 4> bytes{};
        size_t idx = 0;
        int current = 0;
        bool has_digit = false;

        for (char ch : str) {
            if (ch == '.') {
                if (!has_digit || idx >= 3 || current > 255) return std::nullopt;
                bytes[idx++] = static_cast<uint8_t>(current);
                current = 0;
                has_digit = false;
            } else if (ch >= '0' && ch <= '9') {
                current = current * 10 + (ch - '0');
                if (current > 255) return std::nullopt;
                has_digit = true;
            } else {
                return std::nullopt;
            }
        }
        if (!has_digit || idx != 3 || current > 255) return std::nullopt;
        bytes[idx] = static_cast<uint8_t>(current);
        return Ipv4Address(bytes);
    }
};

// IPv6 Address (16 octets)
struct Ipv6Address {
    std::array<uint8_t, 16> octets{};

    constexpr Ipv6Address() = default;
    constexpr explicit Ipv6Address(const std::array<uint8_t, 16>& bytes) : octets(bytes) {}

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            uint16_t word = (static_cast<uint16_t>(octets[i]) << 8) | octets[i + 1];
            oss << std::hex << word;
        }
        return oss.str();
    }

    bool operator==(const Ipv6Address& other) const = default;
    auto operator<=>(const Ipv6Address& other) const = default;
};

// Ethernet II / 802.3 Header
struct EthernetHeader {
    MacAddress dst_mac{};
    MacAddress src_mac{};
    uint16_t ethertype{0};
    uint16_t vlan_id{0}; // 0 if untagged
};

// ARP Packet Header (RFC 826)
struct ArpHeader {
    uint16_t hardware_type{1}; // 1 = Ethernet
    uint16_t protocol_type{0x0800}; // 0x0800 = IPv4
    uint8_t hardware_size{6};
    uint8_t protocol_size{4};
    uint16_t opcode{1}; // 1 = Request, 2 = Reply
    MacAddress sender_mac{};
    Ipv4Address sender_ip{};
    MacAddress target_mac{};
    Ipv4Address target_ip{};

    [[nodiscard]] bool is_request() const { return opcode == 1; }
    [[nodiscard]] bool is_reply() const { return opcode == 2; }
    [[nodiscard]] bool is_gratuitous() const {
        // Gratuitous ARP: sender IP equals target IP, or broadcast target
        return sender_ip == target_ip || target_mac.is_broadcast() || target_mac.is_zero();
    }
};

// IPv4 Header (RFC 791)
struct Ipv4Header {
    uint8_t version{4};
    uint8_t ihl{5}; // in 32-bit words
    uint8_t tos{0};
    uint16_t total_length{0};
    uint16_t id{0};
    uint16_t flags_fragment_offset{0};
    uint8_t ttl{64};
    uint8_t protocol{0}; // 6 = TCP, 17 = UDP, 1 = ICMP
    uint16_t checksum{0};
    Ipv4Address src_ip{};
    Ipv4Address dst_ip{};

    [[nodiscard]] size_t header_bytes() const { return ihl * 4; }
};

// IPv6 Header (RFC 8200)
struct Ipv6Header {
    uint8_t version{6};
    uint8_t traffic_class{0};
    uint32_t flow_label{0};
    uint16_t payload_length{0};
    uint8_t next_header{0}; // 6 = TCP, 17 = UDP, 58 = ICMPv6
    uint8_t hop_limit{64};
    Ipv6Address src_ip{};
    Ipv6Address dst_ip{};
};

// TCP Header (RFC 793, RFC 9293)
struct TcpHeader {
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t seq_num{0};
    uint32_t ack_num{0};
    uint8_t data_offset{5}; // in 32-bit words
    uint16_t flags{0};
    uint16_t window_size{0};
    uint16_t checksum{0};
    uint16_t urgent_pointer{0};

    [[nodiscard]] size_t header_bytes() const { return data_offset * 4; }

    [[nodiscard]] bool fin() const { return (flags & 0x01) != 0; }
    [[nodiscard]] bool syn() const { return (flags & 0x02) != 0; }
    [[nodiscard]] bool rst() const { return (flags & 0x04) != 0; }
    [[nodiscard]] bool psh() const { return (flags & 0x08) != 0; }
    [[nodiscard]] bool ack() const { return (flags & 0x10) != 0; }
    [[nodiscard]] bool urg() const { return (flags & 0x20) != 0; }
    [[nodiscard]] bool ece() const { return (flags & 0x40) != 0; }
    [[nodiscard]] bool cwr() const { return (flags & 0x80) != 0; }
};

// UDP Header (RFC 768)
struct UdpHeader {
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint16_t length{0};
    uint16_t checksum{0};
};

// Fully parsed packet record
struct ParsedPacket {
    uint32_t timestamp_sec{0};
    uint32_t timestamp_usec{0};
    uint32_t incl_len{0};
    uint32_t orig_len{0};

    std::optional<EthernetHeader> ethernet;
    std::optional<ArpHeader> arp;
    std::optional<Ipv4Header> ipv4;
    std::optional<Ipv6Header> ipv6;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;

    std::vector<uint8_t> payload;

    [[nodiscard]] std::string src_endpoint() const {
        std::ostringstream oss;
        if (ipv4) {
            oss << ipv4->src_ip.to_string();
            if (tcp) oss << ":" << tcp->src_port;
            else if (udp) oss << ":" << udp->src_port;
        } else if (ipv6) {
            oss << "[" << ipv6->src_ip.to_string() << "]";
            if (tcp) oss << ":" << tcp->src_port;
            else if (udp) oss << ":" << udp->src_port;
        } else if (arp) {
            oss << arp->sender_ip.to_string();
        } else if (ethernet) {
            oss << ethernet->src_mac.to_string();
        }
        return oss.str();
    }

    [[nodiscard]] std::string dst_endpoint() const {
        std::ostringstream oss;
        if (ipv4) {
            oss << ipv4->dst_ip.to_string();
            if (tcp) oss << ":" << tcp->dst_port;
            else if (udp) oss << ":" << udp->dst_port;
        } else if (ipv6) {
            oss << "[" << ipv6->dst_ip.to_string() << "]";
            if (tcp) oss << ":" << tcp->dst_port;
            else if (udp) oss << ":" << udp->dst_port;
        } else if (arp) {
            oss << arp->target_ip.to_string();
        } else if (ethernet) {
            oss << ethernet->dst_mac.to_string();
        }
        return oss.str();
    }
};

} // namespace netpulse

namespace std {
template <>
struct hash<netpulse::MacAddress> {
    size_t operator()(const netpulse::MacAddress& mac) const noexcept {
        size_t h = 0;
        for (uint8_t b : mac.octets) {
            h = (h * 31) + b;
        }
        return h;
    }
};

template <>
struct hash<netpulse::Ipv4Address> {
    size_t operator()(const netpulse::Ipv4Address& ip) const noexcept {
        return std::hash<uint32_t>{}(ip.to_u32());
    }
};
} // namespace std
