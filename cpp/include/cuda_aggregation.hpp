#pragma once

#include <cstddef>
#include <cstdint>

namespace zerotrust::fl::aggregation::cuda {

inline constexpr std::size_t kMaxTrimmedMeanClients = 1024;

void launch_pairwise_distances(
    std::uintptr_t pointer_table_device,
    std::uintptr_t distances_device,
    std::size_t client_count,
    std::size_t dimension,
    std::uintptr_t stream
);

void launch_trimmed_mean(
    std::uintptr_t pointer_table_device,
    std::uintptr_t output_device,
    std::size_t client_count,
    std::size_t dimension,
    float beta,
    std::uintptr_t stream
);

void launch_average_selected(
    std::uintptr_t pointer_table_device,
    std::uintptr_t selected_indices_device,
    std::uintptr_t output_device,
    std::size_t selected_count,
    std::size_t dimension,
    std::uintptr_t stream
);

[[nodiscard]] int runtime_version();

}  // namespace zerotrust::fl::aggregation::cuda
