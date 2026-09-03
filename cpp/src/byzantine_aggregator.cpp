#include "byzantine_aggregator.hpp"
#include "simd_distance.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace zerotrust::fl::aggregation {
namespace {

std::size_t validate_updates(std::span<const UpdateView> updates) {
    if (updates.empty()) {
        throw std::invalid_argument("at least one model update is required");
    }

    const std::size_t dimension = updates.front().size;
    if (dimension == 0) {
        throw std::invalid_argument("model updates must not be empty");
    }

    for (std::size_t i = 0; i < updates.size(); ++i) {
        if (updates[i].data == nullptr) {
            throw std::invalid_argument("model update " + std::to_string(i) + " has a null data pointer");
        }
        if (updates[i].size != dimension) {
            throw std::invalid_argument("all model updates must have the same number of elements");
        }
    }

    int invalid = 0;
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel for reduction(| : invalid) schedule(static)
#endif
    for (std::ptrdiff_t i = 0; i < static_cast<std::ptrdiff_t>(updates.size()); ++i) {
        const auto& update = updates[static_cast<std::size_t>(i)];
        for (std::size_t d = 0; d < dimension; ++d) {
            if (!std::isfinite(update.data[d])) {
                invalid = 1;
                break;
            }
        }
    }

    if (invalid != 0) {
        throw std::invalid_argument("model updates must contain only finite values");
    }

    return dimension;
}

}  // namespace

const char* simd_backend() noexcept {
    return detail::active_simd_backend();
}

std::vector<float> krum_aggregate(
    std::span<const UpdateView> updates,
    std::size_t byzantine_count,
    std::size_t candidate_count
) {
    const std::size_t dimension = validate_updates(updates);
    const std::size_t n = updates.size();

    if (n < 2 * byzantine_count + 3) {
        throw std::invalid_argument("Krum requires n >= 2*f + 3");
    }

    const std::size_t neighbor_count = n - byzantine_count - 2;
    if (candidate_count == 0 || candidate_count > neighbor_count) {
        throw std::invalid_argument("Multi-Krum candidate count k must satisfy 1 <= k <= n-f-2");
    }

    std::vector<double> distances(n * n, 0.0);
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel for schedule(dynamic, 1)
#endif
    for (std::ptrdiff_t i_raw = 0; i_raw < static_cast<std::ptrdiff_t>(n); ++i_raw) {
        const std::size_t i = static_cast<std::size_t>(i_raw);
        for (std::size_t j = i + 1; j < n; ++j) {
            const double distance = detail::squared_euclidean_distance_simd(
                updates[i].data,
                updates[j].data,
                dimension
            );
            distances[i * n + j] = distance;
            distances[j * n + i] = distance;
        }
    }

    std::vector<double> scores(n, std::numeric_limits<double>::infinity());
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel
#endif
    {
        std::vector<double> nearest;
        nearest.reserve(n - 1);
#ifdef ZTFL_HAS_OPENMP
#pragma omp for schedule(static)
#endif
        for (std::ptrdiff_t i_raw = 0; i_raw < static_cast<std::ptrdiff_t>(n); ++i_raw) {
            const std::size_t i = static_cast<std::size_t>(i_raw);
            nearest.clear();
            for (std::size_t j = 0; j < n; ++j) {
                if (i != j) {
                    nearest.push_back(distances[i * n + j]);
                }
            }

            std::nth_element(
                nearest.begin(),
                nearest.begin() + static_cast<std::ptrdiff_t>(neighbor_count),
                nearest.end()
            );
            scores[i] = std::accumulate(
                nearest.begin(),
                nearest.begin() + static_cast<std::ptrdiff_t>(neighbor_count),
                0.0
            );
        }
    }

    std::vector<std::size_t> indices(n);
    std::iota(indices.begin(), indices.end(), 0);
    const auto score_order = [&scores](std::size_t lhs, std::size_t rhs) {
        if (scores[lhs] == scores[rhs]) {
            return lhs < rhs;
        }
        return scores[lhs] < scores[rhs];
    };
    std::partial_sort(
        indices.begin(),
        indices.begin() + static_cast<std::ptrdiff_t>(candidate_count),
        indices.end(),
        score_order
    );

    if (candidate_count == 1) {
        const auto& selected = updates[indices.front()];
        return std::vector<float>(selected.data, selected.data + selected.size);
    }

    std::vector<float> result(dimension, 0.0F);
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (std::ptrdiff_t d_raw = 0; d_raw < static_cast<std::ptrdiff_t>(dimension); ++d_raw) {
        const std::size_t d = static_cast<std::size_t>(d_raw);
        double sum = 0.0;
        for (std::size_t selected = 0; selected < candidate_count; ++selected) {
            sum += static_cast<double>(updates[indices[selected]].data[d]);
        }
        result[d] = static_cast<float>(sum / static_cast<double>(candidate_count));
    }

    return result;
}

std::vector<float> trimmed_mean_aggregate(std::span<const UpdateView> updates, float beta) {
    const std::size_t dimension = validate_updates(updates);
    const std::size_t n = updates.size();

    if (!std::isfinite(beta) || beta < 0.0F || beta >= 0.5F) {
        throw std::invalid_argument("trim ratio beta must satisfy 0 <= beta < 0.5");
    }

    const std::size_t trim_count = static_cast<std::size_t>(
        std::floor(static_cast<double>(beta) * static_cast<double>(n))
    );
    if (2 * trim_count >= n) {
        throw std::invalid_argument("trim ratio removes every model update");
    }
    const std::size_t retained = n - 2 * trim_count;

    std::vector<float> result(dimension, 0.0F);
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel
#endif
    {
        std::vector<float> values(n);
#ifdef ZTFL_HAS_OPENMP
#pragma omp for schedule(static)
#endif
        for (std::ptrdiff_t d_raw = 0; d_raw < static_cast<std::ptrdiff_t>(dimension); ++d_raw) {
            const std::size_t d = static_cast<std::size_t>(d_raw);
            for (std::size_t i = 0; i < n; ++i) {
                values[i] = updates[i].data[d];
            }
            std::sort(values.begin(), values.end());

            double sum = 0.0;
            for (std::size_t i = trim_count; i < n - trim_count; ++i) {
                sum += static_cast<double>(values[i]);
            }
            result[d] = static_cast<float>(sum / static_cast<double>(retained));
        }
    }

    return result;
}

std::vector<float> median_aggregate(std::span<const UpdateView> updates) {
    const std::size_t dimension = validate_updates(updates);
    const std::size_t n = updates.size();
    const std::size_t middle = n / 2;

    std::vector<float> result(dimension, 0.0F);
#ifdef ZTFL_HAS_OPENMP
#pragma omp parallel
#endif
    {
        std::vector<float> values(n);
#ifdef ZTFL_HAS_OPENMP
#pragma omp for schedule(static)
#endif
        for (std::ptrdiff_t d_raw = 0; d_raw < static_cast<std::ptrdiff_t>(dimension); ++d_raw) {
            const std::size_t d = static_cast<std::size_t>(d_raw);
            for (std::size_t i = 0; i < n; ++i) {
                values[i] = updates[i].data[d];
            }

            std::nth_element(
                values.begin(),
                values.begin() + static_cast<std::ptrdiff_t>(middle),
                values.end()
            );
            const float upper = values[middle];
            if ((n & 1U) != 0U) {
                result[d] = upper;
                continue;
            }

            const float lower = *std::max_element(
                values.begin(),
                values.begin() + static_cast<std::ptrdiff_t>(middle)
            );
            result[d] = static_cast<float>(
                (static_cast<double>(lower) + static_cast<double>(upper)) * 0.5
            );
        }
    }

    return result;
}

}  // namespace zerotrust::fl::aggregation
