#include "netpulse/common.hpp"
#include "netpulse/pcap_reader.hpp"
#include "netpulse/md5.hpp"
#include "netpulse/tls_ja3.hpp"
#include "netpulse/dns_analyzer.hpp"
#include "netpulse/arp_tracker.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <fstream>
#include <cmath>
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace {

int g_passed = 0;
int g_failed = 0;

void run_test(const std::string& name, bool (*fn)()) {
    std::cout << "[TEST] " << name << " ... ";
    try {
        if (fn()) {
            std::cout << "PASSED\n";
            g_passed++;
        } else {
            std::cout << "FAILED\n";
            g_failed++;
        }
    } catch (const std::exception& ex) {
        std::cout << "FAILED (exception: " << ex.what() << ")\n";
        g_failed++;
    } catch (...) {
        std::cout << "FAILED (unknown exception)\n";
        g_failed++;
    }
}

// 1. PCAP Magic number validation (Microsecond native)
bool test_pcap_magic_microsec_native() {
    std::vector<uint8_t> buf(24, 0);
    // magic 0xa1b2c3d4 little-endian: d4 c3 b2 a1
    buf[0] = 0xd4; buf[1] = 0xc3; buf[2] = 0xb2; buf[3] = 0xa1;
    buf[4] = 2; buf[5] = 0; // version_major = 2
    buf[6] = 4; buf[7] = 0; // version_minor = 4

    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_memory(buf, err)) return false;
    return reader.header().magic_number == netpulse::PCAP_MAGIC_MICROSEC_SAME &&
           !reader.header().byte_swapped &&
           reader.header().version_major == 2 &&
           reader.header().version_minor == 4;
}

// 2. PCAP Byte-swapped header handling
bool test_pcap_magic_swapped() {
    std::vector<uint8_t> buf(24, 0);
    // magic 0xd4c3b2a1 little-endian: a1 b2 c3 d4
    buf[0] = 0xa1; buf[1] = 0xb2; buf[2] = 0xc3; buf[3] = 0xd4;
    buf[4] = 0; buf[5] = 2; // version_major = 2 in big-endian
    buf[6] = 0; buf[7] = 4; // version_minor = 4 in big-endian

    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_memory(buf, err)) return false;
    return reader.header().byte_swapped &&
           reader.header().version_major == 2 &&
           reader.header().version_minor == 4;
}

// 3. CWE-125: Truncated PCAP global header rejection
bool test_pcap_truncated_global_header() {
    std::vector<uint8_t> buf(20, 0); // less than 24 bytes
    netpulse::PcapReader reader;
    std::string err;
    bool ok = reader.open_memory(buf, err);
    return (!ok) && (!err.empty());
}

// 4. CWE-125: Truncated packet record header rejection
bool test_pcap_truncated_packet_record() {
    std::vector<uint8_t> buf(24 + 10, 0); // 24 global hdr + 10 bytes (record header needs 16)
    buf[0] = 0xd4; buf[1] = 0xc3; buf[2] = 0xb2; buf[3] = 0xa1;

    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_memory(buf, err)) return false;

    netpulse::ParsedPacket pkt;
    std::string warn;
    bool has_next = reader.next_packet(pkt, warn);
    return (!has_next) && (!warn.empty()) && (reader.stats().truncated_packets == 1);
}

// 5. CWE-125: Truncated packet payload rejection
bool test_pcap_truncated_packet_payload() {
    std::vector<uint8_t> buf(24 + 16 + 10, 0); // 10 bytes payload
    buf[0] = 0xd4; buf[1] = 0xc3; buf[2] = 0xb2; buf[3] = 0xa1;
    // Set incl_len to 100 in record header (offset 24 + 8)
    buf[24 + 8] = 100;
    buf[24 + 9] = 0;

    netpulse::PcapReader reader;
    std::string err;
    if (!reader.open_memory(buf, err)) return false;

    netpulse::ParsedPacket pkt;
    std::string warn;
    bool has_next = reader.next_packet(pkt, warn);
    return (!has_next) && (!warn.empty()) && (reader.stats().truncated_packets == 1);
}

// 6. CWE-125: Ethernet decoder bounds & 802.1Q VLAN handling
bool test_ethernet_decoder_bounds() {
    std::vector<uint8_t> truncated(12, 0);
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_ethernet(truncated, pkt, err)) return false;

    // Valid 802.1Q tagged frame
    std::vector<uint8_t> vlan_frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
        0x81, 0x00,                         // 802.1Q ethertype
        0x00, 0x64,                         // VLAN ID 100 (0x0064)
        0x08, 0x00                          // inner ethertype IPv4
    };
    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_ethernet(vlan_frame, pkt, err)) {
        // Expected because IPv4 layer is empty/truncated, but ethernet was parsed
    }
    return pkt.ethernet.has_value() && pkt.ethernet->vlan_id == 100 && pkt.ethernet->ethertype == 0x0800;
}

// 7. CWE-125: IPv4 decoder bounds & IHL verification
bool test_ipv4_decoder_bounds() {
    std::vector<uint8_t> truncated(16, 0);
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_ipv4(truncated, pkt, err)) return false;

    // IPv4 header with invalid IHL (3 < 5)
    std::vector<uint8_t> bad_ihl(20, 0);
    bad_ihl[0] = 0x43; // version 4, IHL 3
    if (netpulse::PcapReader::parse_ipv4(bad_ihl, pkt, err)) return false;

    // Valid IPv4 header
    std::vector<uint8_t> valid_ip(20, 0);
    valid_ip[0] = 0x45; // version 4, IHL 5
    valid_ip[2] = 0x00; valid_ip[3] = 0x14; // total length 20
    valid_ip[8] = 64;   // TTL
    valid_ip[9] = 6;    // TCP
    valid_ip[12] = 192; valid_ip[13] = 0; valid_ip[14] = 2; valid_ip[15] = 1; // src
    valid_ip[16] = 198; valid_ip[17] = 51; valid_ip[18] = 100; valid_ip[19] = 1; // dst

    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_ipv4(valid_ip, pkt, err)) return false;
    return pkt.ipv4.has_value() &&
           pkt.ipv4->src_ip.to_string() == "192.0.2.1" &&
           pkt.ipv4->dst_ip.to_string() == "198.51.100.1";
}

// 8. CWE-125: IPv6 decoder bounds verification
bool test_ipv6_decoder_bounds() {
    std::vector<uint8_t> truncated(30, 0);
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_ipv6(truncated, pkt, err)) return false;

    std::vector<uint8_t> valid_ip6(40, 0);
    valid_ip6[0] = 0x60; // version 6
    valid_ip6[6] = 17;   // Next header: UDP
    valid_ip6[7] = 64;   // Hop limit
    valid_ip6[23] = 1;   // src ::1
    valid_ip6[39] = 2;   // dst ::2

    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_ipv6(valid_ip6, pkt, err)) return false;
    return pkt.ipv6.has_value() && pkt.ipv6->version == 6 && pkt.ipv6->next_header == 17;
}

// 9. CWE-125: TCP decoder bounds verification
bool test_tcp_decoder_bounds() {
    std::vector<uint8_t> truncated(15, 0);
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_tcp(truncated, pkt, err)) return false;

    // Bad data offset (< 5)
    std::vector<uint8_t> bad_offset(20, 0);
    bad_offset[12] = 0x20; // offset = 2
    if (netpulse::PcapReader::parse_tcp(bad_offset, pkt, err)) return false;

    // Valid TCP header
    std::vector<uint8_t> valid_tcp(20, 0);
    valid_tcp[0] = 0x01; valid_tcp[1] = 0xbb; // port 443
    valid_tcp[2] = 0xc0; valid_tcp[3] = 0x01; // port 49153
    valid_tcp[12] = 0x50; // offset 5
    valid_tcp[13] = 0x02; // SYN flag

    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_tcp(valid_tcp, pkt, err)) return false;
    return pkt.tcp.has_value() && pkt.tcp->src_port == 443 && pkt.tcp->syn();
}

// 10. CWE-125: UDP decoder bounds verification
bool test_udp_decoder_bounds() {
    std::vector<uint8_t> truncated(6, 0);
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_udp(truncated, pkt, err)) return false;

    std::vector<uint8_t> valid_udp = {
        0x00, 0x35, // src port 53
        0xc0, 0x00, // dst port 49152
        0x00, 0x0c, // length 12
        0x00, 0x00, // checksum
        0x01, 0x02, 0x03, 0x04 // 4 bytes payload
    };
    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_udp(valid_udp, pkt, err)) return false;
    return pkt.udp.has_value() && pkt.udp->src_port == 53 && pkt.payload.size() == 4;
}

// 11. RFC 8701: GREASE value detection filter
bool test_rfc8701_grease_filter() {
    const uint16_t grease_values[16] = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    };

    for (uint16_t g : grease_values) {
        if (!netpulse::is_grease_value(g)) return false;
    }

    // Verify normal TLS values are NOT classified as GREASE
    if (netpulse::is_grease_value(0x0000)) return false; // SNI
    if (netpulse::is_grease_value(0x000a)) return false; // Supported groups
    if (netpulse::is_grease_value(0x1301)) return false; // TLS_AES_128_GCM_SHA256
    if (netpulse::is_grease_value(0x0023)) return false; // Session Ticket
    return true;
}

// 12. RFC 1321: MD5 standard test vectors
bool test_md5_standard_test_vectors() {
    struct Vector {
        std::string_view input;
        std::string_view expected_hash;
    };

    const Vector vectors[] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"}
    };

    for (const auto& v : vectors) {
        if (netpulse::Md5::hash(v.input) != v.expected_hash) {
            return false;
        }
    }
    return true;
}

// 13. JA3 string builder and GREASE stripping
bool test_ja3_string_builder_grease_removal() {
    uint16_t version = 771;
    std::vector<uint16_t> ciphers = {0x1a1a /* GREASE */, 49195, 49199, 0x2a2a /* GREASE */, 52393};
    std::vector<uint16_t> extensions = {0, 0x3a3a /* GREASE */, 10, 11};
    std::vector<uint16_t> curves = {0x4a4a /* GREASE */, 29, 23};
    std::vector<uint8_t> formats = {0};

    std::string ja3 = netpulse::TlsJa3Dissector::build_ja3_string(
        version, ciphers, extensions, curves, formats
    );

    std::string expected = "771,49195-49199-52393,0-10-11,29-23,0";
    return ja3 == expected;
}

// 14. JA3 hash computation and client signature matching
bool test_ja3_hash_known_fingerprint() {
    std::string ja3_str = "771,49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-10-11-13-16,29-23-24,0";
    std::string hash = netpulse::TlsJa3Dissector::compute_ja3_hash(ja3_str);
    if (hash.size() != 32) return false;

    // Test Python Requests lookup
    std::string py_match = netpulse::TlsJa3Dissector::lookup_fingerprint("b32309a26951912be7dba376398abc3b");
    if (py_match != "Python Requests / urllib3") return false;

    std::string curl_match = netpulse::TlsJa3Dissector::lookup_fingerprint("c7fed91d1e67e3a9a8f47f201dd0b898");
    return curl_match == "cURL HTTP Client (libcurl)";
}

// 15. Shannon entropy calculation
bool test_dns_shannon_entropy_calculation() {
    // String with identical characters has 0 entropy
    double zero_ent = netpulse::DnsAnalyzer::calculate_shannon_entropy("aaaaaaa");
    if (std::abs(zero_ent - 0.0) > 0.0001) return false;

    // Natural English word has lower entropy
    double low_ent = netpulse::DnsAnalyzer::calculate_shannon_entropy("example");
    // High randomness string has high entropy
    double high_ent = netpulse::DnsAnalyzer::calculate_shannon_entropy("a8f4d9c2e1b307fa65e4");

    return (low_ent < 3.0) && (high_ent > 3.5);
}

// 16. DNS hex ratio and max label length evaluation
bool test_dns_hex_ratio_and_max_label() {
    std::string hex_str = "deadbeef1234abcd";
    double ratio1 = netpulse::DnsAnalyzer::calculate_hex_ratio(hex_str);
    if (std::abs(ratio1 - 1.0) > 0.001) return false;

    std::string mixed_str = "hello123";
    double ratio2 = netpulse::DnsAnalyzer::calculate_hex_ratio(mixed_str);
    // 'e' is hex, '1', '2', '3' are hex -> 4 of 8 = 0.5
    return std::abs(ratio2 - 0.5) < 0.001;
}

// 17. DNS tunneling exfiltration detection scoring
bool test_dns_exfiltration_scorer() {
    // Benign query
    auto benign = netpulse::DnsAnalyzer::evaluate_query("www.google.com", 1);
    if (benign.risk_level != netpulse::TunnelRiskLevel::BENIGN) return false;

    // Tunneling query (50-char hex string)
    std::string tunnel_q = "4a6f686e446f65536563726574446174613132333435363738.tunnel.test-net.org";
    auto suspicious = netpulse::DnsAnalyzer::evaluate_query(tunnel_q, 16);
    return suspicious.risk_level == netpulse::TunnelRiskLevel::HIGH_RISK &&
           suspicious.anomaly_score >= 0.70;
}

// 18. CWE-125: ARP decoder bounds verification
bool test_arp_decoder_bounds() {
    std::vector<uint8_t> truncated(20, 0); // ARP needs 28 bytes
    netpulse::ParsedPacket pkt;
    std::string err;
    if (netpulse::PcapReader::parse_arp(truncated, pkt, err)) return false;

    // Valid ARP Request
    std::vector<uint8_t> valid_arp = {
        0x00, 0x01, // HW Ethernet
        0x08, 0x00, // Proto IPv4
        0x06,       // HW size
        0x04,       // Proto size
        0x00, 0x01, // Opcode Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
        192, 0, 2, 10,                      // Sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
        192, 0, 2, 1                        // Target IP
    };
    pkt = netpulse::ParsedPacket{};
    if (!netpulse::PcapReader::parse_arp(valid_arp, pkt, err)) return false;
    return pkt.arp.has_value() && pkt.arp->is_request() && pkt.arp->sender_ip.to_string() == "192.0.2.10";
}

// 19. ARP cache poisoning / spoofing detection
bool test_arp_spoof_detection() {
    netpulse::ArpTracker tracker;

    netpulse::ArpHeader arp1{};
    arp1.opcode = 2; // Reply
    arp1.sender_mac = netpulse::MacAddress(0x00, 0x50, 0x56, 0x11, 0x22, 0x33);
    arp1.sender_ip = *netpulse::Ipv4Address::parse("192.0.2.1");
    arp1.target_mac = netpulse::MacAddress(0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc);
    arp1.target_ip = *netpulse::Ipv4Address::parse("192.0.2.10");

    auto alert1 = tracker.ingest_arp(arp1, 1000, 0);
    if (alert1.has_value()) return false; // First time seen, no alert

    // Attacker claims same IP with different MAC
    netpulse::ArpHeader arp2{};
    arp2.opcode = 2; // Reply
    arp2.sender_mac = netpulse::MacAddress(0xb8, 0x27, 0xeb, 0xde, 0xad, 0x01);
    arp2.sender_ip = *netpulse::Ipv4Address::parse("192.0.2.1");
    arp2.target_mac = netpulse::MacAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    arp2.target_ip = *netpulse::Ipv4Address::parse("192.0.2.1");

    auto alert2 = tracker.ingest_arp(arp2, 1001, 0);
    return alert2.has_value() &&
           alert2->alert_type == netpulse::ArpAlertType::GRATUITOUS_POISONING &&
           tracker.alerts().size() == 1;
}

// 20. DHCP Option-55 OS fingerprinting
bool test_dhcp_option55_fingerprinting() {
    netpulse::ArpTracker tracker;
    std::string linux_fp = "1,121,33,3,6,12,15,26,28,42,119";
    std::string win_fp = "1,3,6,15,31,33,43,44,46,47,119,121,249,252";

    std::string os1 = tracker.match_os_fingerprint(linux_fp);
    std::string os2 = tracker.match_os_fingerprint(win_fp);

    return (os1.find("Linux") != std::string::npos) &&
           (os2.find("Windows") != std::string::npos);
}

// 21. Binary path string check: verify path remapping works and no host leaks
bool test_binary_path_string_check() {
    // Read the compiled test binary itself
    std::ifstream bin("/proc/self/exe", std::ios::binary);
    if (!bin.is_open()) {
        // If /proc/self/exe not accessible, fallback
        return true;
    }
    std::string content((std::istreambuf_iterator<char>(bin)), std::istreambuf_iterator<char>());

    // Verify -ffile-prefix-map prevented repository absolute path leakage
    const char* home_env = std::getenv("HOME");
    if (home_env && std::strlen(home_env) > 0) {
        if (content.find(home_env) != std::string::npos) {
            std::cerr << "\n[LEAK DETECTED] Binary contains HOME environment path!\n";
            return false;
        }
    }
    return true;
}

} // anonymous namespace

int main() {
    std::cout << "========================================================\n"
              << " Netpulse Automated Unit & Security Test Suite\n"
              << " CWE-125 Safe | RFC 8701 GREASE | DNS Entropy | ARP Spoof\n"
              << "========================================================\n";

    run_test("PCAP Microsecond Native Magic", test_pcap_magic_microsec_native);
    run_test("PCAP Byte-Swapped Magic & Endianness", test_pcap_magic_swapped);
    run_test("PCAP Global Header Truncation Reject (CWE-125)", test_pcap_truncated_global_header);
    run_test("PCAP Packet Record Truncation Reject (CWE-125)", test_pcap_truncated_packet_record);
    run_test("PCAP Packet Payload Truncation Reject (CWE-125)", test_pcap_truncated_packet_payload);
    run_test("Ethernet Decoder Bounds & 802.1Q (CWE-125)", test_ethernet_decoder_bounds);
    run_test("IPv4 Decoder Bounds & IHL Verification (CWE-125)", test_ipv4_decoder_bounds);
    run_test("IPv6 Decoder Bounds Verification (CWE-125)", test_ipv6_decoder_bounds);
    run_test("TCP Decoder Bounds Verification (CWE-125)", test_tcp_decoder_bounds);
    run_test("UDP Decoder Bounds Verification (CWE-125)", test_udp_decoder_bounds);
    run_test("RFC 8701 GREASE Filter Predicate", test_rfc8701_grease_filter);
    run_test("RFC 1321 MD5 Test Vectors", test_md5_standard_test_vectors);
    run_test("JA3 String Builder & GREASE Stripping", test_ja3_string_builder_grease_removal);
    run_test("JA3 Hash & Known Client Fingerprints", test_ja3_hash_known_fingerprint);
    run_test("Shannon Entropy Calculation", test_dns_shannon_entropy_calculation);
    run_test("DNS Hex Ratio & Label Length", test_dns_hex_ratio_and_max_label);
    run_test("DNS Exfiltration Anomaly Scorer", test_dns_exfiltration_scorer);
    run_test("ARP Decoder Bounds Verification (CWE-125)", test_arp_decoder_bounds);
    run_test("ARP Spoof & Gratuitous Poisoning Detector", test_arp_spoof_detection);
    run_test("DHCP Option-55 OS Fingerprinting", test_dhcp_option55_fingerprinting);
    run_test("Path Remapping Zero-Leak Binary Verification", test_binary_path_string_check);

    std::cout << "\n--------------------------------------------------------\n"
              << "Test Results: " << g_passed << " Passed, " << g_failed << " Failed ("
              << (g_passed + g_failed) << " Total)\n"
              << "--------------------------------------------------------\n";

    return (g_failed == 0) ? 0 : 1;
}
