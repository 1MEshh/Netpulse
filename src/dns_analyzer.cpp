#include "netpulse/dns_analyzer.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <array>
#include <sstream>

namespace netpulse {

namespace {

inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

} // anonymous namespace

bool DnsAnalyzer::parse_qname(std::span<const uint8_t> payload,
                              size_t& offset,
                              std::string& out_name,
                              std::string& err_msg) {
    out_name.clear();
    size_t curr = offset;
    bool jumped = false;
    size_t next_offset = 0;
    int jumps_count = 0;
    constexpr int MAX_JUMPS = 10;

    while (curr < payload.size()) {
        uint8_t len = payload[curr];
        if (len == 0) {
            // End of domain name
            if (!jumped) {
                next_offset = curr + 1;
            }
            offset = next_offset;
            return true;
        }

        // Pointer compression check (top 2 bits set: 0xC0)
        if ((len & 0xC0) == 0xC0) {
            if (curr + 1 >= payload.size()) {
                err_msg = "Truncated DNS compression pointer";
                return false;
            }
            if (!jumped) {
                next_offset = curr + 2;
                jumped = true;
            }
            if (++jumps_count > MAX_JUMPS) {
                err_msg = "Exceeded maximum DNS compression pointer jumps (cycle detected)";
                return false;
            }
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | payload[curr + 1]);
            if (ptr >= payload.size()) {
                err_msg = "DNS pointer out of bounds: " + std::to_string(ptr);
                return false;
            }
            curr = ptr;
            continue;
        }

        // Regular label
        curr++;
        if (curr + len > payload.size()) {
            err_msg = "DNS label length exceeds packet payload";
            return false;
        }

        if (!out_name.empty()) {
            out_name += ".";
        }
        out_name.append(reinterpret_cast<const char*>(payload.data() + curr), len);
        curr += len;

        if (!jumped) {
            next_offset = curr;
        }
    }

    err_msg = "Unterminated DNS name";
    return false;
}

std::optional<DnsMessage> DnsAnalyzer::parse_message(std::span<const uint8_t> payload,
                                                    std::string& err_msg) {
    if (payload.size() < 12) {
        err_msg = "DNS packet too small for header (<12 bytes)";
        return std::nullopt;
    }

    const uint8_t* p = payload.data();
    DnsMessage msg{};
    msg.id = read_be16(p);
    msg.flags = read_be16(p + 2);

    msg.is_response = (msg.flags & 0x8000) != 0;
    msg.opcode = static_cast<uint8_t>((msg.flags >> 11) & 0x0F);
    msg.authoritative = (msg.flags & 0x0400) != 0;
    msg.truncated = (msg.flags & 0x0200) != 0;
    msg.recursion_desired = (msg.flags & 0x0100) != 0;
    msg.recursion_available = (msg.flags & 0x0080) != 0;
    msg.rcode = static_cast<uint8_t>(msg.flags & 0x000F);

    uint16_t qdcount = read_be16(p + 4);
    uint16_t ancount = read_be16(p + 6);
    // uint16_t nscount = read_be16(p + 8);
    // uint16_t arcount = read_be16(p + 10);

    size_t offset = 12;

    // Parse Question section
    for (uint16_t i = 0; i < qdcount; ++i) {
        DnsQuestion q{};
        if (!parse_qname(payload, offset, q.name, err_msg)) {
            return std::nullopt;
        }
        if (offset + 4 > payload.size()) {
            err_msg = "Truncated DNS question type/class";
            return std::nullopt;
        }
        q.qtype = read_be16(payload.data() + offset);
        q.qclass = read_be16(payload.data() + offset + 2);
        offset += 4;
        msg.questions.push_back(std::move(q));
    }

    // Parse Answer section (if present)
    for (uint16_t i = 0; i < ancount && offset < payload.size(); ++i) {
        DnsRecord rec{};
        if (!parse_qname(payload, offset, rec.name, err_msg)) {
            break;
        }
        if (offset + 10 > payload.size()) {
            break;
        }
        rec.type = read_be16(payload.data() + offset);
        rec.rclass = read_be16(payload.data() + offset + 2);
        rec.ttl = read_be32(payload.data() + offset + 4);
        uint16_t rdlen = read_be16(payload.data() + offset + 8);
        offset += 10;

        if (offset + rdlen > payload.size()) {
            break;
        }

        rec.rdata.assign(payload.data() + offset, payload.data() + offset + rdlen);

        // Formatted representation for common record types
        if (rec.type == 1 && rdlen == 4) { // A
            rec.formatted_data = Ipv4Address(rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3]).to_string();
        } else if (rec.type == 16 && rdlen > 0) { // TXT
            uint8_t txt_len = rec.rdata[0];
            if (txt_len + 1 <= rdlen) {
                rec.formatted_data.assign(reinterpret_cast<const char*>(rec.rdata.data() + 1), txt_len);
            }
        }
        offset += rdlen;
        msg.answers.push_back(std::move(rec));
    }

    return msg;
}

double DnsAnalyzer::calculate_shannon_entropy(std::string_view text) {
    if (text.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (unsigned char ch : text) {
        freq[ch]++;
    }

    double entropy = 0.0;
    double len = static_cast<double>(text.size());

    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / len;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

double DnsAnalyzer::calculate_hex_ratio(std::string_view text) {
    if (text.empty()) return 0.0;
    size_t hex_chars = 0;
    for (char ch : text) {
        if (std::isxdigit(static_cast<unsigned char>(ch))) {
            hex_chars++;
        }
    }
    return static_cast<double>(hex_chars) / static_cast<double>(text.size());
}

DnsAnalysisReport DnsAnalyzer::evaluate_query(const std::string& fqdn,
                                            uint16_t qtype,
                                            double threshold) {
    DnsAnalysisReport report{};
    report.query_name = fqdn;
    report.query_type = qtype;
    report.total_length = fqdn.size();

    // Split into labels
    std::vector<std::string> labels;
    size_t start = 0;
    while (start < fqdn.size()) {
        size_t dot = fqdn.find('.', start);
        if (dot == std::string::npos) {
            labels.push_back(fqdn.substr(start));
            break;
        }
        labels.push_back(fqdn.substr(start, dot - start));
        start = dot + 1;
    }

    size_t max_label = 0;
    for (const auto& l : labels) {
        max_label = std::max(max_label, l.size());
    }
    report.max_label_length = max_label;

    if (!labels.empty()) {
        report.primary_subdomain = labels[0];
    }

    // Compute Shannon entropy on both subdomain and full domain
    double sub_entropy = calculate_shannon_entropy(report.primary_subdomain);
    double full_entropy = calculate_shannon_entropy(fqdn);
    report.shannon_entropy = std::max(sub_entropy, full_entropy);

    // Compute hex ratio of primary subdomain
    report.hex_ratio = calculate_hex_ratio(report.primary_subdomain);

    // Normalization factors
    // Natural English domain entropy typically ranges from 2.0 to 3.5.
    // Encoded payloads (Base64, Hex, encrypted) produce entropy >= 3.8 to 4.5+.
    double e_norm = std::clamp((report.shannon_entropy - 2.5) / 2.0, 0.0, 1.0);

    // Max label length normalization: standard labels <= 12 chars; tunnel payloads approach 63
    double l_norm = std::clamp(static_cast<double>(std::max<int>(0, static_cast<int>(max_label) - 12)) / 51.0, 0.0, 1.0);

    // Hex ratio factor: pure hex tunnels have ratio close to 1.0
    double h_factor = (report.hex_ratio >= 0.70) ? report.hex_ratio : 0.0;

    // Composite scoring
    double score = (0.45 * e_norm) + (0.35 * l_norm) + (0.20 * h_factor);

    // Tunnel length bonus: elevated entropy combined with abnormal length
    if (max_label >= 35 && report.shannon_entropy >= 3.6) {
        score += 0.15;
    }
    report.anomaly_score = std::clamp(score, 0.0, 1.0);

    // Risk classification
    if (report.anomaly_score >= threshold) {
        report.risk_level = TunnelRiskLevel::HIGH_RISK;
        std::ostringstream ss;
        ss << "High-confidence DNS tunnel: entropy=" << std::fixed << std::setprecision(2)
           << report.shannon_entropy << ", max_label_len=" << report.max_label_length
           << ", hex_ratio=" << report.hex_ratio;
        report.detection_rationale = ss.str();
    } else if (report.anomaly_score >= 0.50) {
        report.risk_level = TunnelRiskLevel::SUSPICIOUS;
        report.detection_rationale = "Elevated entropy or abnormal label length detected";
    } else {
        report.risk_level = TunnelRiskLevel::BENIGN;
        report.detection_rationale = "Nominal DNS query structure";
    }

    return report;
}

std::string DnsAnalyzer::record_type_name(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 255: return "ANY";
        default: return "TYPE" + std::to_string(qtype);
    }
}

} // namespace netpulse
