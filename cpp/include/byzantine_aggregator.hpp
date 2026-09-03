#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace zerotrust::fl::aggregation {

struct UpdateView {
    const float* data{};
    std::size_t size{};
};

[[nodiscard]] std::vector<float> krum_aggregate(
    std::span<const UpdateView> updates,
    std::size_t byzantine_count,
    std::size_t candidate_count
);

[[nodiscard]] std::vector<float> trimmed_mean_aggregate(
    std::span<const UpdateView> updates,
    float beta
);

[[nodiscard]] std::vector<float> median_aggregate(
    std::span<const UpdateView> updates
);

[[nodiscard]] const char* simd_backend() noexcept;

}  // namespace zerotrust::fl::aggregation
