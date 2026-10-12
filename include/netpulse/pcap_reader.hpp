#pragma once

#include "netpulse/common.hpp"
#include <string>
#include <vector>
#include <span>
#include <cstdint>
#include <optional>

namespace netpulse {

constexpr uint32_t PCAP_MAGIC_MICROSEC_SAME = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_MICROSEC_SWAP = 0xd4c3b2a1;
constexpr uint32_t PCAP_MAGIC_NANOSEC_SAME  = 0xa1b23c4d;
constexpr uint32_t PCAP_MAGIC_NANOSEC_SWAP  = 0x4d3cb2a1;

constexpr uint32_t DLT_NULL       = 0;
constexpr uint32_t DLT_EN10MB     = 1;   // Ethernet 10/100/1000 Mbps
constexpr uint32_t DLT_RAW        = 12;  // Raw IP
constexpr uint32_t DLT_LINUX_SLL  = 113; // Linux "cooked" capture v1
constexpr uint32_t DLT_LINUX_SLL2 = 276; // Linux "cooked" capture v2

struct PcapGlobalHeader {
    uint32_t magic_number{0};
    uint16_t version_major{0};
    uint16_t version_minor{0};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{0};
    uint32_t network{0};
    bool byte_swapped{false};
    bool is_nanosec{false};
};

struct PcapStats {
    size_t total_packets{0};
    size_t truncated_packets{0};
    size_t ethernet_count{0};
    size_t arp_count{0};
    size_t ipv4_count{0};
    size_t ipv6_count{0};
    size_t tcp_count{0};
    size_t udp_count{0};
    uint64_t total_wire_bytes{0};
};

class PcapReader {
public:
    PcapReader() = default;

    bool open_file(const std::string& filepath, std::string& err_msg);
    bool open_memory(std::span<const uint8_t> buffer, std::string& err_msg);

    bool next_packet(ParsedPacket& packet, std::string& warning);
    std::vector<ParsedPacket> read_all();

    [[nodiscard]] const PcapGlobalHeader& header() const { return header_; }
    [[nodiscard]] const PcapStats& stats() const { return stats_; }

    static bool parse_packet_data(std::span<const uint8_t> data,
                                  uint32_t link_type,
                                  ParsedPacket& out_pkt,
                                  std::string& err);

    static bool parse_ethernet(std::span<const uint8_t> frame,
                               ParsedPacket& out_pkt,
                               std::string& err);

    static bool parse_ipv4(std::span<const uint8_t> data,
                           ParsedPacket& out_pkt,
                           std::string& err);

    static bool parse_ipv6(std::span<const uint8_t> data,
                           ParsedPacket& out_pkt,
                           std::string& err);

    static bool parse_arp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err);

    static bool parse_tcp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err);

    static bool parse_udp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err);

private:
    PcapGlobalHeader header_{};
    PcapStats stats_{};
    std::vector<uint8_t> file_buffer_{};
    std::span<const uint8_t> buffer_view_{};
    size_t offset_{0};
};

} // namespace netpulse
