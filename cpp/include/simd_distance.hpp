#pragma once

#include <cstddef>

namespace zerotrust::fl::aggregation::detail {

[[nodiscard]] double squared_euclidean_distance_simd(
    const float* lhs,
    const float* rhs,
    std::size_t size
) noexcept;

[[nodiscard]] const char* active_simd_backend() noexcept;

}  // namespace zerotrust::fl::aggregation::detail
