#pragma once

#include "netpulse/common.hpp"
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <cstdint>
#include <cmath>

namespace netpulse {

struct DnsQuestion {
    std::string name;
    uint16_t qtype{0};
    uint16_t qclass{0};
};

struct DnsRecord {
    std::string name;
    uint16_t type{0};
    uint16_t rclass{0};
    uint32_t ttl{0};
    std::vector<uint8_t> rdata;
    std::string formatted_data;
};

struct DnsMessage {
    uint16_t id{0};
    uint16_t flags{0};
    bool is_response{false};
    uint8_t opcode{0};
    bool authoritative{false};
    bool truncated{false};
    bool recursion_desired{false};
    bool recursion_available{false};
    uint8_t rcode{0};

    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
};

enum class TunnelRiskLevel {
    BENIGN,
    SUSPICIOUS,
    HIGH_RISK
};

struct DnsAnalysisReport {
    std::string query_name;
    std::string primary_subdomain;
    uint16_t query_type{0};
    double shannon_entropy{0.0};
    size_t max_label_length{0};
    size_t total_length{0};
    double hex_ratio{0.0};
    double anomaly_score{0.0};
    TunnelRiskLevel risk_level{TunnelRiskLevel::BENIGN};
    std::string detection_rationale;

    [[nodiscard]] std::string risk_level_string() const {
        switch (risk_level) {
            case TunnelRiskLevel::BENIGN: return "BENIGN";
            case TunnelRiskLevel::SUSPICIOUS: return "SUSPICIOUS";
            case TunnelRiskLevel::HIGH_RISK: return "HIGH_RISK_TUNNEL";
        }
        return "UNKNOWN";
    }
};

class DnsAnalyzer {
public:
    DnsAnalyzer() = default;

    // Dissects DNS message from UDP or TCP payload
    static std::optional<DnsMessage> parse_message(std::span<const uint8_t> payload,
                                                   std::string& err_msg);

    // Mathematical entropy computation: H(X) = -sum(p * log2(p))
    static double calculate_shannon_entropy(std::string_view text);

    // Ratio of hex characters [0-9a-fA-F] to total length
    static double calculate_hex_ratio(std::string_view text);

    // Compute composite DNS exfiltration score
    static DnsAnalysisReport evaluate_query(const std::string& fqdn,
                                          uint16_t qtype,
                                          double threshold = 0.65);

    // Helper to format DNS type IDs (1 -> A, 28 -> AAAA, 16 -> TXT, etc.)
    static std::string record_type_name(uint16_t qtype);

private:
    static bool parse_qname(std::span<const uint8_t> full_payload,
                            size_t& offset,
                            std::string& out_name,
                            std::string& err_msg);
};

} // namespace netpulse
