#pragma once

#include "netpulse/common.hpp"
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <cstdint>

namespace netpulse {

// RFC 8701 GREASE filter predicate
[[nodiscard]] constexpr bool is_grease_value(uint16_t val) noexcept {
    return ((val & 0x0F0F) == 0x0A0A) && ((val >> 8) == (val & 0xFF));
}

struct Ja3Result {
    uint16_t client_version{0};
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> elliptic_curves;
    std::vector<uint8_t> ec_point_formats;

    std::string ja3_string;
    std::string ja3_hash;

    std::string server_name;
    std::vector<std::string> alpn_protocols;
    std::string matched_client;
};

class TlsJa3Dissector {
public:
    // Dissects TLS Record + Handshake ClientHello from TCP payload or buffer
    static std::optional<Ja3Result> dissect_client_hello(std::span<const uint8_t> payload,
                                                         std::string& err_msg);

    // Build raw JA3 string from parsed components (applies GREASE filtering)
    static std::string build_ja3_string(uint16_t client_version,
                                        std::span<const uint16_t> ciphers,
                                        std::span<const uint16_t> extensions,
                                        std::span<const uint16_t> curves,
                                        std::span<const uint8_t> point_formats);

    // Compute MD5 digest from JA3 string
    static std::string compute_ja3_hash(const std::string& ja3_str);

    // Match JA3 hash against built-in database
    static std::string lookup_fingerprint(const std::string& ja3_hash);
};

} // namespace netpulse
