#pragma once

#include <string>
#include <string_view>
#include <span>
#include <cstdint>
#include <array>

namespace netpulse {

class Md5 {
public:
    Md5();

    void update(std::span<const uint8_t> data);
    void update(std::string_view str);
    void finalize();

    [[nodiscard]] std::array<uint8_t, 16> digest() const;
    [[nodiscard]] std::string hexdigest() const;

    static std::string hash(std::string_view input);
    static std::string hash(std::span<const uint8_t> input);

private:
    void transform(const uint8_t block[64]);

    uint32_t state_[4]{};
    uint64_t count_{0};
    uint8_t buffer_[64]{};
    std::array<uint8_t, 16> digest_{};
    bool finalized_{false};
};

} // namespace netpulse
