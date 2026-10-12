#pragma once

#include "netpulse/common.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>
#include <span>

namespace netpulse {

enum class ArpAlertType {
    IP_CONFLICT_SPOOF,
    GRATUITOUS_POISONING
};

struct ArpAlert {
    uint32_t timestamp_sec{0};
    uint32_t timestamp_usec{0};
    Ipv4Address victim_ip;
    MacAddress original_mac;
    MacAddress attacker_mac;
    ArpAlertType alert_type;
    std::string description;
};

struct HostArpState {
    Ipv4Address ip;
    MacAddress mac;
    std::string vendor;
    uint32_t first_seen_sec{0};
    uint32_t last_seen_sec{0};
    size_t packet_count{0};
    std::vector<MacAddress> mac_history;
};

struct DhcpFingerprint {
    MacAddress client_mac;
    std::string hostname;
    std::string vendor_class;
    std::vector<uint8_t> option55_list;
    std::string option55_str;
    std::string identified_os;
};

class ArpTracker {
public:
    ArpTracker() = default;

    // Process parsed packet and inspect ARP & DHCP events
    void process_packet(const ParsedPacket& pkt);

    // Explicitly ingest an ARP header
    std::optional<ArpAlert> ingest_arp(const ArpHeader& arp, uint32_t ts_sec = 0, uint32_t ts_usec = 0);

    // Ingest DHCP packet payload (UDP payload on port 67/68)
    std::optional<DhcpFingerprint> ingest_dhcp(std::span<const uint8_t> payload, const MacAddress& frame_src);

    // Query current ARP state
    [[nodiscard]] const std::unordered_map<std::string, HostArpState>& table() const { return table_; }
    [[nodiscard]] const std::vector<ArpAlert>& alerts() const { return alerts_; }
    [[nodiscard]] const std::unordered_map<MacAddress, DhcpFingerprint>& dhcp_profiles() const { return dhcp_profiles_; }

    // OUI resolution helper
    static std::string lookup_vendor(const MacAddress& mac);

    // Fingerprint helper from option 55 comma-separated string
    static std::string match_os_fingerprint(const std::string& opt55);

private:
    std::unordered_map<std::string, HostArpState> table_;
    std::vector<ArpAlert> alerts_;
    std::unordered_map<MacAddress, DhcpFingerprint> dhcp_profiles_;
};

} // namespace netpulse
