#include "netpulse/pcap_reader.hpp"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace netpulse {

namespace {

inline uint16_t bswap16(uint16_t x) {
    return static_cast<uint16_t>((x << 8) | (x >> 8));
}

inline uint32_t bswap32(uint32_t x) {
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8) |
           ((x & 0x00FF0000u) >> 8) |
           ((x & 0xFF000000u) >> 24);
}

inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

} // anonymous namespace

bool PcapReader::open_file(const std::string& filepath, std::string& err_msg) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        err_msg = "Failed to open PCAP file: " + filepath;
        return false;
    }

    std::streamsize file_size = file.tellg();
    if (file_size < 0) {
        err_msg = "Invalid file size";
        return false;
    }

    file_buffer_.resize(static_cast<size_t>(file_size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(file_buffer_.data()), file_size)) {
        err_msg = "Failed to read PCAP file content";
        file_buffer_.clear();
        return false;
    }

    return open_memory(std::span<const uint8_t>(file_buffer_), err_msg);
}

bool PcapReader::open_memory(std::span<const uint8_t> buffer, std::string& err_msg) {
    buffer_view_ = buffer;
    offset_ = 0;
    stats_ = PcapStats{};

    if (buffer.size() < 24) {
        err_msg = "PCAP buffer too small for global header (need 24 bytes, got " +
                  std::to_string(buffer.size()) + ")";
        return false;
    }

    const uint8_t* p = buffer.data();
    uint32_t raw_magic = read_le32(p);

    if (raw_magic == PCAP_MAGIC_MICROSEC_SAME) {
        header_.magic_number = PCAP_MAGIC_MICROSEC_SAME;
        header_.byte_swapped = false;
        header_.is_nanosec = false;
    } else if (raw_magic == PCAP_MAGIC_MICROSEC_SWAP) {
        header_.magic_number = PCAP_MAGIC_MICROSEC_SWAP;
        header_.byte_swapped = true;
        header_.is_nanosec = false;
    } else if (raw_magic == PCAP_MAGIC_NANOSEC_SAME) {
        header_.magic_number = PCAP_MAGIC_NANOSEC_SAME;
        header_.byte_swapped = false;
        header_.is_nanosec = true;
    } else if (raw_magic == PCAP_MAGIC_NANOSEC_SWAP) {
        header_.magic_number = PCAP_MAGIC_NANOSEC_SWAP;
        header_.byte_swapped = true;
        header_.is_nanosec = true;
    } else {
        err_msg = "Invalid PCAP magic number: 0x" + [&]() {
            std::ostringstream ss;
            ss << std::hex << raw_magic;
            return ss.str();
        }();
        return false;
    }

    auto parse_u16 = [this](const uint8_t* ptr) -> uint16_t {
        uint16_t v = read_le16(ptr);
        return header_.byte_swapped ? bswap16(v) : v;
    };
    auto parse_u32 = [this](const uint8_t* ptr) -> uint32_t {
        uint32_t v = read_le32(ptr);
        return header_.byte_swapped ? bswap32(v) : v;
    };

    header_.version_major = parse_u16(p + 4);
    header_.version_minor = parse_u16(p + 6);
    header_.thiszone = static_cast<int32_t>(parse_u32(p + 8));
    header_.sigfigs = parse_u32(p + 12);
    header_.snaplen = parse_u32(p + 16);
    header_.network = parse_u32(p + 20);

    offset_ = 24;
    return true;
}

bool PcapReader::next_packet(ParsedPacket& packet, std::string& warning) {
    warning.clear();
    if (offset_ + 16 > buffer_view_.size()) {
        if (offset_ < buffer_view_.size()) {
            warning = "Truncated PCAP packet header at offset " + std::to_string(offset_);
            stats_.truncated_packets++;
        }
        return false;
    }

    const uint8_t* p = buffer_view_.data() + offset_;

    auto parse_u32 = [this](const uint8_t* ptr) -> uint32_t {
        uint32_t v = read_le32(ptr);
        return header_.byte_swapped ? bswap32(v) : v;
    };

    uint32_t ts_sec = parse_u32(p);
    uint32_t ts_usec = parse_u32(p + 4);
    uint32_t incl_len = parse_u32(p + 8);
    uint32_t orig_len = parse_u32(p + 12);

    offset_ += 16;

    if (offset_ + incl_len > buffer_view_.size()) {
        warning = "Truncated packet payload: incl_len " + std::to_string(incl_len) +
                  " exceeds buffer limit";
        stats_.truncated_packets++;
        offset_ = buffer_view_.size(); // exhaust buffer
        return false;
    }

    std::span<const uint8_t> pkt_data = buffer_view_.subspan(offset_, incl_len);
    offset_ += incl_len;

    packet = ParsedPacket{};
    packet.timestamp_sec = ts_sec;
    packet.timestamp_usec = ts_usec;
    packet.incl_len = incl_len;
    packet.orig_len = orig_len;

    stats_.total_packets++;
    stats_.total_wire_bytes += orig_len;

    std::string parse_err;
    if (!parse_packet_data(pkt_data, header_.network, packet, parse_err)) {
        warning = "Packet parse warning: " + parse_err;
    }

    if (packet.ethernet) stats_.ethernet_count++;
    if (packet.arp) stats_.arp_count++;
    if (packet.ipv4) stats_.ipv4_count++;
    if (packet.ipv6) stats_.ipv6_count++;
    if (packet.tcp) stats_.tcp_count++;
    if (packet.udp) stats_.udp_count++;

    return true;
}

std::vector<ParsedPacket> PcapReader::read_all() {
    std::vector<ParsedPacket> packets;
    ParsedPacket pkt;
    std::string warn;
    while (next_packet(pkt, warn)) {
        packets.push_back(std::move(pkt));
    }
    return packets;
}

bool PcapReader::parse_packet_data(std::span<const uint8_t> data,
                                  uint32_t link_type,
                                  ParsedPacket& out_pkt,
                                  std::string& err) {
    if (link_type == DLT_EN10MB) {
        return parse_ethernet(data, out_pkt, err);
    } else if (link_type == DLT_RAW) {
        if (data.empty()) {
            err = "Empty RAW link layer";
            return false;
        }
        uint8_t version = (data[0] >> 4) & 0x0F;
        if (version == 4) {
            return parse_ipv4(data, out_pkt, err);
        } else if (version == 6) {
            return parse_ipv6(data, out_pkt, err);
        } else {
            err = "Unknown RAW IP version: " + std::to_string(version);
            return false;
        }
    } else if (link_type == DLT_LINUX_SLL) {
        if (data.size() < 16) {
            err = "Truncated Linux SLL header";
            return false;
        }
        uint16_t proto = read_be16(data.data() + 14);
        std::span<const uint8_t> payload = data.subspan(16);
        if (proto == 0x0800) {
            return parse_ipv4(payload, out_pkt, err);
        } else if (proto == 0x86DD) {
            return parse_ipv6(payload, out_pkt, err);
        } else if (proto == 0x0806) {
            return parse_arp(payload, out_pkt, err);
        }
        out_pkt.payload.assign(payload.begin(), payload.end());
        return true;
    }

    // Default: raw payload
    out_pkt.payload.assign(data.begin(), data.end());
    return true;
}

bool PcapReader::parse_ethernet(std::span<const uint8_t> frame,
                               ParsedPacket& out_pkt,
                               std::string& err) {
    if (frame.size() < 14) {
        err = "Truncated Ethernet frame (<14 bytes)";
        return false;
    }

    EthernetHeader eth{};
    std::memcpy(eth.dst_mac.octets.data(), frame.data(), 6);
    std::memcpy(eth.src_mac.octets.data(), frame.data() + 6, 6);
    eth.ethertype = read_be16(frame.data() + 12);

    size_t payload_offset = 14;

    // 802.1Q VLAN Tag check
    if (eth.ethertype == 0x8100) {
        if (frame.size() < 18) {
            err = "Truncated 802.1Q VLAN tagged frame (<18 bytes)";
            return false;
        }
        uint16_t tci = read_be16(frame.data() + 14);
        eth.vlan_id = tci & 0x0FFF;
        eth.ethertype = read_be16(frame.data() + 16);
        payload_offset = 18;
    }

    out_pkt.ethernet = eth;
    std::span<const uint8_t> next_layer = frame.subspan(payload_offset);

    if (eth.ethertype == 0x0800) {
        return parse_ipv4(next_layer, out_pkt, err);
    } else if (eth.ethertype == 0x86DD) {
        return parse_ipv6(next_layer, out_pkt, err);
    } else if (eth.ethertype == 0x0806) {
        return parse_arp(next_layer, out_pkt, err);
    }

    out_pkt.payload.assign(next_layer.begin(), next_layer.end());
    return true;
}

bool PcapReader::parse_ipv4(std::span<const uint8_t> data,
                           ParsedPacket& out_pkt,
                           std::string& err) {
    if (data.size() < 20) {
        err = "Truncated IPv4 header (<20 bytes)";
        return false;
    }

    uint8_t ver_ihl = data[0];
    uint8_t version = (ver_ihl >> 4) & 0x0F;
    uint8_t ihl = ver_ihl & 0x0F;

    if (version != 4) {
        err = "Invalid IPv4 version: " + std::to_string(version);
        return false;
    }
    if (ihl < 5) {
        err = "Invalid IPv4 IHL (" + std::to_string(ihl) + " < 5)";
        return false;
    }

    size_t header_len = static_cast<size_t>(ihl) * 4;
    if (data.size() < header_len) {
        err = "Truncated IPv4 header options (data " + std::to_string(data.size()) +
              " < IHL " + std::to_string(header_len) + ")";
        return false;
    }

    Ipv4Header ip{};
    ip.version = version;
    ip.ihl = ihl;
    ip.tos = data[1];
    ip.total_length = read_be16(data.data() + 2);
    ip.id = read_be16(data.data() + 4);
    ip.flags_fragment_offset = read_be16(data.data() + 6);
    ip.ttl = data[8];
    ip.protocol = data[9];
    ip.checksum = read_be16(data.data() + 10);
    std::memcpy(ip.src_ip.octets.data(), data.data() + 12, 4);
    std::memcpy(ip.dst_ip.octets.data(), data.data() + 16, 4);

    out_pkt.ipv4 = ip;

    // Available L4 payload
    size_t available = data.size() - header_len;
    if (ip.total_length >= header_len) {
        size_t expected_payload = ip.total_length - header_len;
        available = std::min(available, expected_payload);
    }

    std::span<const uint8_t> l4_data = data.subspan(header_len, available);

    if (ip.protocol == 6) {
        if (l4_data.empty()) return true;
        return parse_tcp(l4_data, out_pkt, err);
    } else if (ip.protocol == 17) {
        if (l4_data.empty()) return true;
        return parse_udp(l4_data, out_pkt, err);
    }

    out_pkt.payload.assign(l4_data.begin(), l4_data.end());
    return true;
}

bool PcapReader::parse_ipv6(std::span<const uint8_t> data,
                           ParsedPacket& out_pkt,
                           std::string& err) {
    if (data.size() < 40) {
        err = "Truncated IPv6 header (<40 bytes)";
        return false;
    }

    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 6) {
        err = "Invalid IPv6 version: " + std::to_string(version);
        return false;
    }

    Ipv6Header ip6{};
    ip6.version = 6;
    ip6.traffic_class = static_cast<uint8_t>(((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F));
    ip6.flow_label = (static_cast<uint32_t>(data[1] & 0x0F) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8) |
                     data[3];
    ip6.payload_length = read_be16(data.data() + 4);
    ip6.next_header = data[6];
    ip6.hop_limit = data[7];
    std::memcpy(ip6.src_ip.octets.data(), data.data() + 8, 16);
    std::memcpy(ip6.dst_ip.octets.data(), data.data() + 24, 16);

    out_pkt.ipv6 = ip6;

    size_t available = data.size() - 40;
    available = std::min(available, static_cast<size_t>(ip6.payload_length));

    std::span<const uint8_t> l4_data = data.subspan(40, available);

    if (ip6.next_header == 6) {
        if (l4_data.empty()) return true;
        return parse_tcp(l4_data, out_pkt, err);
    } else if (ip6.next_header == 17) {
        if (l4_data.empty()) return true;
        return parse_udp(l4_data, out_pkt, err);
    }

    out_pkt.payload.assign(l4_data.begin(), l4_data.end());
    return true;
}

bool PcapReader::parse_arp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err) {
    if (data.size() < 28) {
        err = "Truncated ARP packet (<28 bytes)";
        return false;
    }

    ArpHeader arp{};
    arp.hardware_type = read_be16(data.data());
    arp.protocol_type = read_be16(data.data() + 2);
    arp.hardware_size = data[4];
    arp.protocol_size = data[5];
    arp.opcode = read_be16(data.data() + 6);

    if (arp.hardware_size != 6 || arp.protocol_size != 4) {
        err = "Unsupported ARP HW/Protocol address length";
        return false;
    }

    std::memcpy(arp.sender_mac.octets.data(), data.data() + 8, 6);
    std::memcpy(arp.sender_ip.octets.data(), data.data() + 14, 4);
    std::memcpy(arp.target_mac.octets.data(), data.data() + 18, 6);
    std::memcpy(arp.target_ip.octets.data(), data.data() + 24, 4);

    out_pkt.arp = arp;
    if (data.size() > 28) {
        out_pkt.payload.assign(data.begin() + 28, data.end());
    }
    return true;
}

bool PcapReader::parse_tcp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err) {
    if (data.size() < 20) {
        err = "Truncated TCP header (<20 bytes)";
        return false;
    }

    TcpHeader tcp{};
    tcp.src_port = read_be16(data.data());
    tcp.dst_port = read_be16(data.data() + 2);
    tcp.seq_num = read_be32(data.data() + 4);
    tcp.ack_num = read_be32(data.data() + 8);

    uint8_t data_offset_res = data[12];
    tcp.data_offset = (data_offset_res >> 4) & 0x0F;
    if (tcp.data_offset < 5) {
        err = "Invalid TCP data offset (" + std::to_string(tcp.data_offset) + " < 5)";
        return false;
    }

    size_t header_len = static_cast<size_t>(tcp.data_offset) * 4;
    if (data.size() < header_len) {
        err = "Truncated TCP header options (data " + std::to_string(data.size()) +
              " < offset " + std::to_string(header_len) + ")";
        return false;
    }

    tcp.flags = static_cast<uint16_t>(((data[12] & 0x0F) << 8) | data[13]);
    tcp.window_size = read_be16(data.data() + 14);
    tcp.checksum = read_be16(data.data() + 16);
    tcp.urgent_pointer = read_be16(data.data() + 18);

    out_pkt.tcp = tcp;

    if (data.size() > header_len) {
        out_pkt.payload.assign(data.begin() + header_len, data.end());
    }
    return true;
}

bool PcapReader::parse_udp(std::span<const uint8_t> data,
                          ParsedPacket& out_pkt,
                          std::string& err) {
    if (data.size() < 8) {
        err = "Truncated UDP header (<8 bytes)";
        return false;
    }

    UdpHeader udp{};
    udp.src_port = read_be16(data.data());
    udp.dst_port = read_be16(data.data() + 2);
    udp.length = read_be16(data.data() + 4);
    udp.checksum = read_be16(data.data() + 6);

    out_pkt.udp = udp;

    size_t available = data.size() - 8;
    if (udp.length >= 8) {
        available = std::min(available, static_cast<size_t>(udp.length - 8));
    }

    if (available > 0) {
        out_pkt.payload.assign(data.begin() + 8, data.begin() + 8 + available);
    }
    return true;
}

} // namespace netpulse
