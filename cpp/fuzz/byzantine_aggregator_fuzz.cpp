#include "byzantine_aggregator.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

using zerotrust::fl::aggregation::UpdateView;
using zerotrust::fl::aggregation::krum_aggregate;
using zerotrust::fl::aggregation::median_aggregate;
using zerotrust::fl::aggregation::trimmed_mean_aggregate;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size < 4) {
        return 0;
    }

    const std::size_t update_count = 1 + (data[0] % 16U);
    const std::size_t dimension = 1 + (data[1] % 64U);
    const std::size_t required = update_count * dimension * sizeof(float);
    if (size - 4 < required) {
        return 0;
    }

    std::vector<float> storage(update_count * dimension);
    std::memcpy(storage.data(), data + 4, required);

    std::vector<UpdateView> updates;
    updates.reserve(update_count);
    for (std::size_t index = 0; index < update_count; ++index) {
        updates.push_back(UpdateView{
            storage.data() + index * dimension,
            dimension,
        });
    }

    try {
        switch (data[2] % 3U) {
            case 0:
                (void)median_aggregate(std::span<const UpdateView>(updates));
                break;
            case 1: {
                const float beta = static_cast<float>(data[3] % 50U) / 100.0F;
                (void)trimmed_mean_aggregate(std::span<const UpdateView>(updates), beta);
                break;
            }
            default: {
                const std::size_t max_byzantine = update_count >= 3 ? (update_count - 3) / 2 : 0;
                const std::size_t byzantine = max_byzantine == 0 ? 0 : data[3] % (max_byzantine + 1);
                if (update_count < 2 * byzantine + 3) {
                    break;
                }
                const std::size_t neighbor_count = update_count - byzantine - 2;
                const std::size_t candidates = 1 + (data[2] % neighbor_count);
                (void)krum_aggregate(
                    std::span<const UpdateView>(updates),
                    byzantine,
                    candidates
                );
                break;
            }
        }
    } catch (...) {
        // Invalid/non-finite inputs are expected to fail closed. Sanitizer or
        // memory-safety failures still terminate the fuzz process.
    }

    return 0;
}
