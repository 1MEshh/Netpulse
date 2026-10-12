#include "netpulse/tls_ja3.hpp"
#include "netpulse/md5.hpp"
#include <sstream>
#include <unordered_map>

namespace netpulse {

namespace {

inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t read_be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

} // anonymous namespace

std::string TlsJa3Dissector::build_ja3_string(uint16_t client_version,
                                              std::span<const uint16_t> ciphers,
                                              std::span<const uint16_t> extensions,
                                              std::span<const uint16_t> curves,
                                              std::span<const uint8_t> point_formats) {
    std::ostringstream oss;

    // 1. SSLVersion (decimal)
    oss << client_version << ",";

    // 2. CipherSuites (decimal separated by -, GREASE stripped)
    bool first = true;
    for (uint16_t cs : ciphers) {
        if (is_grease_value(cs)) continue;
        if (!first) oss << "-";
        oss << cs;
        first = false;
    }
    oss << ",";

    // 3. Extensions (decimal separated by -, GREASE stripped)
    first = true;
    for (uint16_t ext : extensions) {
        if (is_grease_value(ext)) continue;
        if (!first) oss << "-";
        oss << ext;
        first = false;
    }
    oss << ",";

    // 4. EllipticCurves / Supported Groups (decimal separated by -, GREASE stripped)
    first = true;
    for (uint16_t cv : curves) {
        if (is_grease_value(cv)) continue;
        if (!first) oss << "-";
        oss << cv;
        first = false;
    }
    oss << ",";

    // 5. EllipticCurvePointFormats (decimal separated by -)
    first = true;
    for (uint8_t pf : point_formats) {
        if (!first) oss << "-";
        oss << static_cast<int>(pf);
        first = false;
    }

    return oss.str();
}

std::string TlsJa3Dissector::compute_ja3_hash(const std::string& ja3_str) {
    return Md5::hash(ja3_str);
}

std::string TlsJa3Dissector::lookup_fingerprint(const std::string& ja3_hash) {
    static const std::unordered_map<std::string, std::string> KNOWN_JA3 = {
        {"b32309a26951912be7dba376398abc3b", "Python Requests / urllib3"},
        {"c7fed91d1e67e3a9a8f47f201dd0b898", "cURL HTTP Client (libcurl)"},
        {"a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike C2 Beacon (Default Malleable)"},
        {"72a589da586844d7f0818ce684948eea", "Cobalt Strike Windows HTTPS Beacon"},
        {"03eb60ca0457aa27e7f9ff36c6ad8dcf", "Metasploit Meterpreter Reverse HTTPS Stager"},
        {"4d7a28d6f22da2e8ee700073081b8301", "TrickBot Banking Trojan C2 Agent"},
        {"1a90c42735766e4a2c51088d87cc4f97", "Emotet Loader C2 Channel"},
        {"cd08e31494f9531f560d64c695473da9", "Google Chrome 110+ (Windows Desktop)"},
        {"b386946a5a44d1ddcc843bc75336df1a", "Mozilla Firefox 115+ ESR / Desktop"},
        {"66918128f1b9b03303d77c6f2eefd128", "Apple Safari / macOS WebKit"},
        {"e7d705a3286e19ea42f587b344ee6865", "Go Standard Library http.Client"},
        {"3b5074b1b310a084efebe8c1276337aa", "PowerShell Invoke-WebRequest / WinINet"}
    };

    auto it = KNOWN_JA3.find(ja3_hash);
    if (it != KNOWN_JA3.end()) {
        return it->second;
    }
    return "Unknown TLS Client";
}

std::optional<Ja3Result> TlsJa3Dissector::dissect_client_hello(std::span<const uint8_t> payload,
                                                              std::string& err_msg) {
    // Minimum TLS Record + Handshake ClientHello size:
    // 5 bytes Record Header + 4 bytes Handshake Header + 2 version + 32 random + 1 session_len = 44 bytes
    if (payload.size() < 44) {
        err_msg = "Payload too small for TLS ClientHello (<44 bytes)";
        return std::nullopt;
    }

    const uint8_t* p = payload.data();
    size_t len = payload.size();

    // Check TLS Record Content Type: 0x16 = Handshake
    uint8_t content_type = p[0];
    if (content_type != 0x16) {
        err_msg = "Not a TLS Handshake record (type " + std::to_string(content_type) + ")";
        return std::nullopt;
    }

    uint16_t record_len = read_be16(p + 3);
    if (len < static_cast<size_t>(5 + record_len)) {
        // Truncated record or partial segment; we proceed with available bytes up to record_len
        len = std::min(len, static_cast<size_t>(5 + record_len));
    }

    size_t offset = 5;
    if (offset >= len) {
        err_msg = "Empty TLS Record payload";
        return std::nullopt;
    }

    // Handshake Type: 0x01 = ClientHello
    uint8_t hs_type = p[offset];
    if (hs_type != 0x01) {
        err_msg = "Not a TLS ClientHello message (handshake type " + std::to_string(hs_type) + ")";
        return std::nullopt;
    }

    if (offset + 4 > len) {
        err_msg = "Truncated Handshake header";
        return std::nullopt;
    }

    uint32_t hs_len = read_be24(p + offset + 1);
    offset += 4;

    if (offset + hs_len > len) {
        // Partial handshake message
        hs_len = static_cast<uint32_t>(len - offset);
    }

    size_t hs_end = offset + hs_len;

    // Client Version (2 bytes)
    if (offset + 2 > hs_end) {
        err_msg = "Truncated ClientHello version";
        return std::nullopt;
    }
    uint16_t client_version = read_be16(p + offset);
    offset += 2;

    // Random (32 bytes)
    if (offset + 32 > hs_end) {
        err_msg = "Truncated ClientHello random";
        return std::nullopt;
    }
    offset += 32;

    // Session ID
    if (offset + 1 > hs_end) {
        err_msg = "Truncated ClientHello session ID length";
        return std::nullopt;
    }
    uint8_t session_id_len = p[offset++];
    if (offset + session_id_len > hs_end) {
        err_msg = "Truncated ClientHello session ID";
        return std::nullopt;
    }
    offset += session_id_len;

    // Cipher Suites
    if (offset + 2 > hs_end) {
        err_msg = "Truncated Cipher Suites length";
        return std::nullopt;
    }
    uint16_t cs_len = read_be16(p + offset);
    offset += 2;

    if (offset + cs_len > hs_end) {
        err_msg = "Truncated Cipher Suites list";
        return std::nullopt;
    }

    std::vector<uint16_t> ciphers;
    ciphers.reserve(cs_len / 2);
    for (size_t i = 0; i + 1 < cs_len; i += 2) {
        ciphers.push_back(read_be16(p + offset + i));
    }
    offset += cs_len;

    // Compression Methods
    if (offset + 1 > hs_end) {
        err_msg = "Truncated Compression Methods length";
        return std::nullopt;
    }
    uint8_t comp_len = p[offset++];
    if (offset + comp_len > hs_end) {
        err_msg = "Truncated Compression Methods list";
        return std::nullopt;
    }
    offset += comp_len;

    std::vector<uint16_t> extensions;
    std::vector<uint16_t> elliptic_curves;
    std::vector<uint8_t> ec_point_formats;
    std::string sni_hostname;
    std::vector<std::string> alpn_list;

    // Extensions (if present)
    if (offset + 2 <= hs_end) {
        uint16_t ext_total_len = read_be16(p + offset);
        offset += 2;

        size_t ext_end = std::min(offset + ext_total_len, hs_end);

        while (offset + 4 <= ext_end) {
            uint16_t ext_type = read_be16(p + offset);
            uint16_t ext_len = read_be16(p + offset + 2);
            offset += 4;

            if (offset + ext_len > ext_end) {
                // Extension data truncated; record type and terminate
                extensions.push_back(ext_type);
                break;
            }

            extensions.push_back(ext_type);
            const uint8_t* ext_data = p + offset;

            // Extension 0x0000: Server Name Indication (SNI)
            if (ext_type == 0x0000 && ext_len >= 5) {
                uint16_t list_len = read_be16(ext_data);
                if (list_len + 2 <= ext_len && ext_data[2] == 0x00 /* host_name */) {
                    uint16_t name_len = read_be16(ext_data + 3);
                    if (5 + name_len <= ext_len) {
                        sni_hostname.assign(reinterpret_cast<const char*>(ext_data + 5), name_len);
                    }
                }
            }
            // Extension 0x000A: Supported Groups / Elliptic Curves
            else if (ext_type == 0x000A && ext_len >= 2) {
                uint16_t groups_len = read_be16(ext_data);
                size_t num_groups = std::min<size_t>(groups_len, ext_len - 2) / 2;
                elliptic_curves.reserve(num_groups);
                for (size_t g = 0; g < num_groups; ++g) {
                    elliptic_curves.push_back(read_be16(ext_data + 2 + g * 2));
                }
            }
            // Extension 0x000B: EC Point Formats
            else if (ext_type == 0x000B && ext_len >= 1) {
                uint8_t pf_len = ext_data[0];
                size_t num_pf = std::min<size_t>(pf_len, ext_len - 1);
                ec_point_formats.reserve(num_pf);
                for (size_t f = 0; f < num_pf; ++f) {
                    ec_point_formats.push_back(ext_data[1 + f]);
                }
            }
            // Extension 0x0010: ALPN
            else if (ext_type == 0x0010 && ext_len >= 2) {
                uint16_t alpn_len = read_be16(ext_data);
                size_t alpn_off = 2;
                size_t alpn_limit = std::min<size_t>(2 + alpn_len, ext_len);
                while (alpn_off + 1 <= alpn_limit) {
                    uint8_t proto_len = ext_data[alpn_off++];
                    if (alpn_off + proto_len <= alpn_limit) {
                        alpn_list.emplace_back(reinterpret_cast<const char*>(ext_data + alpn_off), proto_len);
                        alpn_off += proto_len;
                    } else {
                        break;
                    }
                }
            }

            offset += ext_len;
        }
    }

    Ja3Result res{};
    res.client_version = client_version;
    res.cipher_suites = std::move(ciphers);
    res.extensions = std::move(extensions);
    res.elliptic_curves = std::move(elliptic_curves);
    res.ec_point_formats = std::move(ec_point_formats);
    res.server_name = std::move(sni_hostname);
    res.alpn_protocols = std::move(alpn_list);

    res.ja3_string = build_ja3_string(res.client_version,
                                      res.cipher_suites,
                                      res.extensions,
                                      res.elliptic_curves,
                                      res.ec_point_formats);
    res.ja3_hash = compute_ja3_hash(res.ja3_string);
    res.matched_client = lookup_fingerprint(res.ja3_hash);

    return res;
}

} // namespace netpulse
