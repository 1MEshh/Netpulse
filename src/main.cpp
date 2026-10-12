#include "netpulse/pcap_reader.hpp"
#include "netpulse/tls_ja3.hpp"
#include "netpulse/dns_analyzer.hpp"
#include "netpulse/arp_tracker.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <csignal>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t g_running = 1;

void handle_signal(int) {
    g_running = 0;
}

void print_banner() {
    std::cout << "========================================================================\n"
              << " Netpulse — High-Performance Network Telemetry & Threat Hunting Engine\n"
              << " Standard C++20 | CWE-125 Safe | JA3 RFC 8701 | DNS Entropy Scorer\n"
              << "========================================================================\n\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <command> [options]\n\n"
              << "Commands:\n"
              << "  analyze-pcap <path.pcap>           Run full multi-layer analysis on capture\n"
              << "  live-sniff <interface>             Sniff raw packets in real-time on network interface\n"
              << "  ja3-profile <path.pcap>            Extract and fingerprint TLS ClientHello handshakes\n"
              << "  dns-tunnel-check <file> [--thresh] Scan DNS queries for covert exfiltration tunnels\n\n"
              << "Options:\n"
              << "  --threshold <float>                Anomaly score threshold (default: 0.65)\n"
              << "  -h, --help                         Show this help message\n";
}

int cmd_analyze_pcap(const std::string& path) {
    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_file(path, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 1;
    }

    netpulse::ArpTracker arp_tracker;
    std::vector<netpulse::Ja3Result> ja3_results;
    std::vector<std::pair<netpulse::ParsedPacket, netpulse::DnsAnalysisReport>> dns_reports;

    netpulse::ParsedPacket pkt;
    std::string warn;
    while (reader.next_packet(pkt, warn)) {
        arp_tracker.process_packet(pkt);

        // TLS JA3 Inspection on TCP packets
        if (pkt.tcp && !pkt.payload.empty()) {
            std::string tls_err;
            auto ja3 = netpulse::TlsJa3Dissector::dissect_client_hello(pkt.payload, tls_err);
            if (ja3) {
                ja3_results.push_back(std::move(*ja3));
            }
        }

        // DNS Inspection on UDP port 53 or TCP port 53
        if ((pkt.udp && (pkt.udp->src_port == 53 || pkt.udp->dst_port == 53)) ||
            (pkt.tcp && (pkt.tcp->src_port == 53 || pkt.tcp->dst_port == 53))) {
            std::string dns_err;
            auto dns = netpulse::DnsAnalyzer::parse_message(pkt.payload, dns_err);
            if (dns) {
                for (const auto& q : dns->questions) {
                    auto rep = netpulse::DnsAnalyzer::evaluate_query(q.name, q.qtype);
                    dns_reports.emplace_back(pkt, std::move(rep));
                }
            }
        }
    }

    const auto& stats = reader.stats();
    std::cout << "[CAPTURE SUMMARY]\n"
              << "  Total Packets:     " << stats.total_packets << "\n"
              << "  Ethernet Frames:   " << stats.ethernet_count << "\n"
              << "  IPv4 Packets:      " << stats.ipv4_count << "\n"
              << "  IPv6 Packets:      " << stats.ipv6_count << "\n"
              << "  TCP Segments:      " << stats.tcp_count << "\n"
              << "  UDP Datagrams:     " << stats.udp_count << "\n"
              << "  ARP Packets:       " << stats.arp_count << "\n"
              << "  Total Wire Bytes:  " << stats.total_wire_bytes << " bytes\n"
              << "  Truncated Packets: " << stats.truncated_packets << "\n\n";

    // ARP Table & Alerts
    std::cout << "[PASSIVE LAN INVENTORY & ARP TRACKING]\n";
    std::cout << std::left << std::setw(18) << "IP Address"
              << std::setw(20) << "MAC Address"
              << std::setw(28) << "Vendor / OUI"
              << std::setw(8) << "Packets" << "\n";
    std::cout << std::string(74, '-') << "\n";
    for (const auto& [ip, state] : arp_tracker.table()) {
        std::cout << std::left << std::setw(18) << ip
                  << std::setw(20) << state.mac.to_string()
                  << std::setw(28) << state.vendor
                  << std::setw(8) << state.packet_count << "\n";
    }
    std::cout << "\n";

    if (!arp_tracker.alerts().empty()) {
        std::cout << "[SECURITY ALERTS: ARP SPOOFING / MITM]\n";
        for (const auto& a : arp_tracker.alerts()) {
            std::cout << "  [ALERT] " << a.description << "\n";
        }
        std::cout << "\n";
    }

    // DHCP Profiles
    if (!arp_tracker.dhcp_profiles().empty()) {
        std::cout << "[DHCP OPTION-55 OS FINGERPRINTS]\n";
        for (const auto& [mac, dhcp] : arp_tracker.dhcp_profiles()) {
            std::cout << "  MAC: " << mac.to_string()
                      << " | Hostname: " << (dhcp.hostname.empty() ? "(none)" : dhcp.hostname)
                      << " | Fingerprinted OS: " << dhcp.identified_os << "\n";
        }
        std::cout << "\n";
    }

    // TLS Handshakes
    std::cout << "[TLS CLIENTHELLO JA3 PROFILES]\n";
    if (ja3_results.empty()) {
        std::cout << "  No TLS ClientHello handshakes recorded.\n\n";
    } else {
        std::cout << std::left << std::setw(34) << "JA3 MD5 Digest"
                  << std::setw(24) << "SNI Hostname"
                  << std::setw(30) << "Identified Client" << "\n";
        std::cout << std::string(88, '-') << "\n";
        for (const auto& j : ja3_results) {
            std::cout << std::left << std::setw(34) << j.ja3_hash
                      << std::setw(24) << (j.server_name.empty() ? "(empty)" : j.server_name)
                      << std::setw(30) << j.matched_client << "\n";
        }
        std::cout << "\n";
    }

    // DNS Analysis
    std::cout << "[DNS EXFILTRATION & ENTROPY AUDIT]\n";
    if (dns_reports.empty()) {
        std::cout << "  No DNS transactions observed.\n\n";
    } else {
        std::cout << std::left << std::setw(42) << "Query Name"
                  << std::setw(8) << "Type"
                  << std::setw(10) << "Entropy"
                  << std::setw(10) << "HexRatio"
                  << std::setw(8) << "Score"
                  << std::setw(16) << "Verdict" << "\n";
        std::cout << std::string(94, '-') << "\n";
        for (const auto& [p, r] : dns_reports) {
            std::string qname = r.query_name;
            if (qname.size() > 39) {
                qname = qname.substr(0, 36) + "...";
            }
            std::cout << std::left << std::setw(42) << qname
                      << std::setw(8) << netpulse::DnsAnalyzer::record_type_name(r.query_type)
                      << std::fixed << std::setprecision(2) << std::setw(10) << r.shannon_entropy
                      << std::setw(10) << r.hex_ratio
                      << std::setw(8) << r.anomaly_score
                      << std::setw(16) << r.risk_level_string() << "\n";
        }
        std::cout << "\n";
    }

    return 0;
}

int cmd_ja3_profile(const std::string& path) {
    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_file(path, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 1;
    }

    std::cout << std::left << std::setw(24) << "Flow (Src -> Dst)"
              << std::setw(34) << "JA3 MD5 Digest"
              << std::setw(22) << "SNI"
              << std::setw(28) << "Client Match" << "\n";
    std::cout << std::string(108, '-') << "\n";

    netpulse::ParsedPacket pkt;
    std::string warn;
    size_t count = 0;
    while (reader.next_packet(pkt, warn)) {
        if (pkt.tcp && !pkt.payload.empty()) {
            std::string tls_err;
            auto ja3 = netpulse::TlsJa3Dissector::dissect_client_hello(pkt.payload, tls_err);
            if (ja3) {
                count++;
                std::string flow = pkt.src_endpoint() + "->" + (pkt.ipv4 ? pkt.ipv4->dst_ip.to_string() : "dst");
                if (flow.size() > 22) flow = flow.substr(0, 21);

                std::cout << std::left << std::setw(24) << flow
                          << std::setw(34) << ja3->ja3_hash
                          << std::setw(22) << (ja3->server_name.empty() ? "(none)" : ja3->server_name)
                          << std::setw(28) << ja3->matched_client << "\n";
                std::cout << "  Raw JA3: " << ja3->ja3_string << "\n\n";
            }
        }
    }

    std::cout << "[INFO] Total ClientHello fingerprints identified: " << count << "\n";
    return 0;
}

int cmd_dns_tunnel_check(const std::string& path, double threshold) {
    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_file(path, err)) {
        std::cerr << "[ERROR] " << err << "\n";
        return 1;
    }

    std::cout << "[DNS EXFILTRATION DETECTOR (Threshold: " << std::fixed << std::setprecision(2) << threshold << ")]\n\n";
    std::cout << std::left << std::setw(46) << "Domain Query"
              << std::setw(8) << "Type"
              << std::setw(10) << "Entropy"
              << std::setw(10) << "MaxLabel"
              << std::setw(10) << "HexRatio"
              << std::setw(8) << "Score"
              << std::setw(18) << "Verdict" << "\n";
    std::cout << std::string(110, '-') << "\n";

    netpulse::ParsedPacket pkt;
    std::string warn;
    size_t suspicious_count = 0;

    while (reader.next_packet(pkt, warn)) {
        if ((pkt.udp && (pkt.udp->src_port == 53 || pkt.udp->dst_port == 53)) ||
            (pkt.tcp && (pkt.tcp->src_port == 53 || pkt.tcp->dst_port == 53))) {
            std::string dns_err;
            auto dns = netpulse::DnsAnalyzer::parse_message(pkt.payload, dns_err);
            if (dns) {
                for (const auto& q : dns->questions) {
                    auto rep = netpulse::DnsAnalyzer::evaluate_query(q.name, q.qtype, threshold);
                    if (rep.risk_level != netpulse::TunnelRiskLevel::BENIGN) {
                        suspicious_count++;
                    }

                    std::string display_name = rep.query_name;
                    if (display_name.size() > 43) {
                        display_name = display_name.substr(0, 40) + "...";
                    }

                    std::cout << std::left << std::setw(46) << display_name
                              << std::setw(8) << netpulse::DnsAnalyzer::record_type_name(rep.query_type)
                              << std::fixed << std::setprecision(2) << std::setw(10) << rep.shannon_entropy
                              << std::setw(10) << rep.max_label_length
                              << std::setw(10) << rep.hex_ratio
                              << std::setw(8) << rep.anomaly_score
                              << std::setw(18) << rep.risk_level_string() << "\n";

                    if (rep.risk_level == netpulse::TunnelRiskLevel::HIGH_RISK) {
                        std::cout << "  --> Alert: " << rep.detection_rationale << "\n";
                    }
                }
            }
        }
    }

    std::cout << "\n[INFO] Audit complete. Suspicious/High-Risk queries: " << suspicious_count << "\n";
    return 0;
}

int cmd_live_sniff(const std::string& interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[ERROR] Failed to open AF_PACKET raw socket (requires root / CAP_NET_RAW): "
                  << std::strerror(errno) << "\n";
        return 1;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[ERROR] Failed to get interface index for '" << interface << "': "
                  << std::strerror(errno) << "\n";
        close(sock);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "[INFO] Sniffing live on interface '" << interface << "' (Press Ctrl+C to terminate)...\n\n";

    netpulse::ArpTracker arp_tracker;
    std::vector<uint8_t> buffer(65536);
    uint64_t packet_counter = 0;

    while (g_running) {
        ssize_t bytes_read = recvfrom(sock, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (bytes_read <= 0) {
            if (errno == EINTR) break;
            continue;
        }

        packet_counter++;
        netpulse::ParsedPacket pkt{};
        std::string parse_err;
        if (!netpulse::PcapReader::parse_packet_data(std::span<const uint8_t>(buffer.data(), bytes_read),
                                                     netpulse::DLT_EN10MB,
                                                     pkt,
                                                     parse_err)) {
            continue;
        }

        // ARP check
        if (pkt.arp) {
            auto alert = arp_tracker.ingest_arp(*pkt.arp);
            if (alert) {
                std::cout << "[SECURITY ALERT - ARP] " << alert->description << "\n";
            }
        }

        // TLS JA3 check
        if (pkt.tcp && !pkt.payload.empty()) {
            std::string tls_err;
            auto ja3 = netpulse::TlsJa3Dissector::dissect_client_hello(pkt.payload, tls_err);
            if (ja3) {
                std::cout << "[TLS CLIENTHELLO] " << pkt.src_endpoint() << " -> "
                          << ja3->ja3_hash << " (" << ja3->matched_client << ") SNI: "
                          << (ja3->server_name.empty() ? "(none)" : ja3->server_name) << "\n";
            }
        }

        // DNS check
        if (pkt.udp && (pkt.udp->src_port == 53 || pkt.udp->dst_port == 53)) {
            std::string dns_err;
            auto dns = netpulse::DnsAnalyzer::parse_message(pkt.payload, dns_err);
            if (dns) {
                for (const auto& q : dns->questions) {
                    auto rep = netpulse::DnsAnalyzer::evaluate_query(q.name, q.qtype);
                    if (rep.risk_level != netpulse::TunnelRiskLevel::BENIGN) {
                        std::cout << "[DNS EXFIL DETECTED] Query: " << rep.query_name
                                  << " Score: " << rep.anomaly_score
                                  << " Verdict: " << rep.risk_level_string() << "\n";
                    }
                }
            }
        }
    }

    close(sock);
    std::cout << "\n[INFO] Sniffer stopped. Total packets inspected: " << packet_counter << "\n";
    return 0;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help") {
        print_usage(argv[0]);
        return 0;
    }

    if (cmd == "analyze-pcap") {
        if (argc < 3) {
            std::cerr << "[ERROR] Missing path to PCAP file\n";
            return 1;
        }
        return cmd_analyze_pcap(argv[2]);
    } else if (cmd == "ja3-profile") {
        if (argc < 3) {
            std::cerr << "[ERROR] Missing path to PCAP file\n";
            return 1;
        }
        return cmd_ja3_profile(argv[2]);
    } else if (cmd == "dns-tunnel-check") {
        if (argc < 3) {
            std::cerr << "[ERROR] Missing path to PCAP file\n";
            return 1;
        }
        double threshold = 0.65;
        if (argc >= 5 && std::string(argv[3]) == "--threshold") {
            try {
                threshold = std::stod(argv[4]);
            } catch (...) {
                std::cerr << "[ERROR] Invalid threshold argument\n";
                return 1;
            }
        }
        return cmd_dns_tunnel_check(argv[2], threshold);
    } else if (cmd == "live-sniff") {
        if (argc < 3) {
            std::cerr << "[ERROR] Missing interface name (e.g. eth0, wlan0)\n";
            return 1;
        }
        return cmd_live_sniff(argv[2]);
    } else {
        std::cerr << "[ERROR] Unknown command: " << cmd << "\n\n";
        print_usage(argv[0]);
        return 1;
    }
}
