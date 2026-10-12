#include "netpulse/arp_tracker.hpp"
#include <sstream>
#include <cstring>

namespace netpulse {

std::string ArpTracker::lookup_vendor(const MacAddress& mac) {
    std::string prefix = mac.oui_prefix();
    static const std::unordered_map<std::string, std::string> OUI_TABLE = {
        {"00:50:56", "VMware, Inc."},
        {"00:0c:29", "VMware, Inc."},
        {"00:05:69", "VMware, Inc."},
        {"08:00:27", "Oracle VirtualBox"},
        {"b8:27:eb", "Raspberry Pi Foundation"},
        {"dc:a6:32", "Raspberry Pi Foundation"},
        {"e4:5f:01", "Raspberry Pi Foundation"},
        {"ac:de:48", "Apple, Inc."},
        {"f0:18:98", "Apple, Inc."},
        {"3c:07:54", "Apple, Inc."},
        {"a4:83:e7", "Apple, Inc."},
        {"00:1a:2b", "Google LLC"},
        {"f4:f5:d8", "Google LLC"},
        {"3c:22:fb", "Google LLC"},
        {"00:15:5d", "Microsoft Corporation (Hyper-V)"},
        {"00:1a:a0", "Dell Inc."},
        {"70:69:79", "Dell Inc."},
        {"00:0c:e6", "Intel Corporation"},
        {"00:1e:67", "Intel Corporation"},
        {"00:1c:73", "Arista Networks"},
        {"00:00:0c", "Cisco Systems, Inc."},
        {"00:01:42", "Cisco Systems, Inc."},
        {"00:01:43", "Cisco Systems, Inc."}
    };

    auto it = OUI_TABLE.find(prefix);
    if (it != OUI_TABLE.end()) {
        return it->second;
    }
    return "Unknown Vendor";
}

std::string ArpTracker::match_os_fingerprint(const std::string& opt55) {
    if (opt55 == "1,3,6,15,31,33,43,44,46,47,119,121,249,252" ||
        opt55.find("1,3,6,15,31,33,43") == 0) {
        return "Microsoft Windows 10 / 11";
    }
    if (opt55 == "1,15,3,6,44,46,47,31,33,121,249,252,43" ||
        opt55.find("1,15,3,6,44,46") == 0) {
        return "Microsoft Windows 7 / 8 / Server";
    }
    if (opt55 == "1,121,33,3,6,12,15,26,28,42,119" ||
        opt55.find("1,121,33,3,6") == 0) {
        return "Linux (Debian / Ubuntu / systemd-networkd)";
    }
    if (opt55 == "1,28,2,3,15,6,119,12,44,47,26,121,42" ||
        opt55.find("1,28,2,3,15") == 0) {
        return "Linux (RHEL / CentOS / Fedora)";
    }
    if (opt55 == "1,3,6,15,119,252,95,44,46" ||
        opt55.find("1,3,6,15,119,252,95") == 0) {
        return "Apple macOS / iOS";
    }
    if (opt55 == "1,3,6,12,15,28,42" ||
        opt55.find("1,3,6,12,15,28") == 0) {
        return "Google Android";
    }
    return "Generic DHCP Client";
}

void ArpTracker::process_packet(const ParsedPacket& pkt) {
    if (pkt.arp) {
        ingest_arp(*pkt.arp, pkt.timestamp_sec, pkt.timestamp_usec);
    }

    // Inspect DHCP traffic (UDP 67 or 68)
    if (pkt.udp && (pkt.udp->src_port == 67 || pkt.udp->src_port == 68 ||
                    pkt.udp->dst_port == 67 || pkt.udp->dst_port == 68)) {
        MacAddress frame_src = pkt.ethernet ? pkt.ethernet->src_mac : MacAddress{};
        ingest_dhcp(pkt.payload, frame_src);
    }
}

std::optional<ArpAlert> ArpTracker::ingest_arp(const ArpHeader& arp,
                                              uint32_t ts_sec,
                                              uint32_t ts_usec) {
    if (arp.sender_ip.is_zero()) {
        return std::nullopt; // RFC 5227 DAD probe
    }

    std::string ip_str = arp.sender_ip.to_string();
    auto it = table_.find(ip_str);

    if (it != table_.end()) {
        HostArpState& state = it->second;
        if (!(state.mac == arp.sender_mac)) {
            // IP conflict detected: existing IP claimed by a different MAC address
            ArpAlert alert{};
            alert.timestamp_sec = ts_sec;
            alert.timestamp_usec = ts_usec;
            alert.victim_ip = arp.sender_ip;
            alert.original_mac = state.mac;
            alert.attacker_mac = arp.sender_mac;

            if (arp.is_gratuitous()) {
                alert.alert_type = ArpAlertType::GRATUITOUS_POISONING;
                alert.description = "Gratuitous ARP cache poisoning: IP " + ip_str +
                                    " reassigned from " + state.mac.to_string() +
                                    " to " + arp.sender_mac.to_string();
            } else {
                alert.alert_type = ArpAlertType::IP_CONFLICT_SPOOF;
                alert.description = "ARP spoofing / IP collision: IP " + ip_str +
                                    " claimed by new MAC " + arp.sender_mac.to_string() +
                                    " (previously " + state.mac.to_string() + ")";
            }

            alerts_.push_back(alert);

            // Record history and update current active mapping
            state.mac_history.push_back(arp.sender_mac);
            state.mac = arp.sender_mac;
            state.vendor = lookup_vendor(arp.sender_mac);
            state.last_seen_sec = ts_sec;
            state.packet_count++;

            return alert;
        }

        state.last_seen_sec = ts_sec;
        state.packet_count++;
        return std::nullopt;
    }

    // New host observation
    HostArpState new_state{};
    new_state.ip = arp.sender_ip;
    new_state.mac = arp.sender_mac;
    new_state.vendor = lookup_vendor(arp.sender_mac);
    new_state.first_seen_sec = ts_sec;
    new_state.last_seen_sec = ts_sec;
    new_state.packet_count = 1;
    new_state.mac_history.push_back(arp.sender_mac);

    table_.emplace(ip_str, std::move(new_state));
    return std::nullopt;
}

std::optional<DhcpFingerprint> ArpTracker::ingest_dhcp(std::span<const uint8_t> payload,
                                                      const MacAddress& frame_src) {
    if (payload.size() < 240) {
        return std::nullopt; // BOOTP header (236) + Magic Cookie (4)
    }

    // Magic Cookie validation: 0x63, 0x82, 0x53, 0x63
    if (payload[236] != 0x63 || payload[237] != 0x82 ||
        payload[238] != 0x53 || payload[239] != 0x63) {
        return std::nullopt;
    }

    DhcpFingerprint fp{};

    // Extract client MAC from BOOTP chaddr (offset 28)
    std::memcpy(fp.client_mac.octets.data(), payload.data() + 28, 6);
    if (fp.client_mac.is_zero()) {
        fp.client_mac = frame_src;
    }

    size_t offset = 240;
    while (offset < payload.size()) {
        uint8_t tag = payload[offset++];
        if (tag == 0) continue; // Pad option
        if (tag == 255) break;  // End option

        if (offset >= payload.size()) break;
        uint8_t opt_len = payload[offset++];
        if (offset + opt_len > payload.size()) break;

        const uint8_t* opt_data = payload.data() + offset;

        // Option 12: Host Name
        if (tag == 12 && opt_len > 0) {
            fp.hostname.assign(reinterpret_cast<const char*>(opt_data), opt_len);
        }
        // Option 60: Vendor Class Identifier
        else if (tag == 60 && opt_len > 0) {
            fp.vendor_class.assign(reinterpret_cast<const char*>(opt_data), opt_len);
        }
        // Option 55: Parameter Request List
        else if (tag == 55 && opt_len > 0) {
            fp.option55_list.assign(opt_data, opt_data + opt_len);
            std::ostringstream ss;
            for (size_t i = 0; i < opt_len; ++i) {
                if (i > 0) ss << ",";
                ss << static_cast<int>(opt_data[i]);
            }
            fp.option55_str = ss.str();
        }

        offset += opt_len;
    }

    if (!fp.option55_str.empty()) {
        fp.identified_os = match_os_fingerprint(fp.option55_str);
        dhcp_profiles_[fp.client_mac] = fp;
        return fp;
    }

    return std::nullopt;
}

} // namespace netpulse
