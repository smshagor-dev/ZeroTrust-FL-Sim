#include "cuda_aggregation.hpp"

#include <cuda_runtime.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace zerotrust::fl::aggregation::cuda {
namespace {

using PointerWord = std::uint64_t;
static_assert(sizeof(std::uintptr_t) == sizeof(PointerWord));

[[noreturn]] void throw_cuda_error(cudaError_t status, const char* operation) {
    throw std::runtime_error(
        std::string(operation) + " failed: " + cudaGetErrorString(status)
    );
}

void check_launch(const char* operation) {
    const cudaError_t status = cudaGetLastError();
    if (status != cudaSuccess) {
        throw_cuda_error(status, operation);
    }
}

__device__ const float* resolve_update(
    const PointerWord* pointer_table,
    std::size_t index
) {
    return reinterpret_cast<const float*>(
        static_cast<std::uintptr_t>(pointer_table[index])
    );
}

__global__ void pairwise_distance_kernel(
    const PointerWord* pointer_table,
    double* distances,
    std::size_t client_count,
    std::size_t dimension
) {
    const std::size_t i = static_cast<std::size_t>(blockIdx.x);
    const std::size_t j = static_cast<std::size_t>(blockIdx.y);
    if (i >= client_count || j >= client_count || j <= i) {
        return;
    }

    const float* lhs = resolve_update(pointer_table, i);
    const float* rhs = resolve_update(pointer_table, j);

    double local_sum = 0.0;
    for (
        std::size_t coordinate = static_cast<std::size_t>(threadIdx.x);
        coordinate < dimension;
        coordinate += static_cast<std::size_t>(blockDim.x)
    ) {
        const double delta = static_cast<double>(lhs[coordinate]) -
                             static_cast<double>(rhs[coordinate]);
        local_sum += delta * delta;
    }

    extern __shared__ double scratch[];
    scratch[threadIdx.x] = local_sum;
    __syncthreads();

    for (unsigned int stride = blockDim.x / 2; stride > 0; stride >>= 1U) {
        if (threadIdx.x < stride) {
            scratch[threadIdx.x] += scratch[threadIdx.x + stride];
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        const double value = scratch[0];
        distances[i * client_count + j] = value;
        distances[j * client_count + i] = value;
    }
}

__global__ void trimmed_mean_kernel(
    const PointerWord* pointer_table,
    float* output,
    std::size_t client_count,
    std::size_t dimension,
    std::size_t trim_count
) {
    extern __shared__ double values[];
    const std::size_t retained = client_count - 2 * trim_count;

    for (
        std::size_t coordinate = static_cast<std::size_t>(blockIdx.x);
        coordinate < dimension;
        coordinate += static_cast<std::size_t>(gridDim.x)
    ) {
        const std::size_t lane = static_cast<std::size_t>(threadIdx.x);
        if (lane < client_count) {
            values[lane] = static_cast<double>(resolve_update(pointer_table, lane)[coordinate]);
        } else {
            values[lane] = std::numeric_limits<double>::infinity();
        }
        __syncthreads();

        for (unsigned int width = 2; width <= blockDim.x; width <<= 1U) {
            for (unsigned int stride = width >> 1U; stride > 0; stride >>= 1U) {
                const unsigned int partner = threadIdx.x ^ stride;
                if (partner > threadIdx.x) {
                    const bool ascending = (threadIdx.x & width) == 0U;
                    const double self_value = values[threadIdx.x];
                    const double partner_value = values[partner];
                    if ((self_value > partner_value) == ascending) {
                        values[threadIdx.x] = partner_value;
                        values[partner] = self_value;
                    }
                }
                __syncthreads();
            }
        }

        double contribution = 0.0;
        if (lane < retained) {
            contribution = values[trim_count + lane];
        }
        __syncthreads();
        values[lane] = contribution;
        __syncthreads();

        for (unsigned int stride = blockDim.x / 2; stride > 0; stride >>= 1U) {
            if (threadIdx.x < stride) {
                values[threadIdx.x] += values[threadIdx.x + stride];
            }
            __syncthreads();
        }

        if (threadIdx.x == 0) {
            output[coordinate] = static_cast<float>(
                values[0] / static_cast<double>(retained)
            );
        }
        __syncthreads();
    }
}

__global__ void average_selected_kernel(
    const PointerWord* pointer_table,
    const std::int64_t* selected_indices,
    float* output,
    std::size_t selected_count,
    std::size_t dimension
) {
    for (
        std::size_t coordinate = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
        coordinate < dimension;
        coordinate += static_cast<std::size_t>(gridDim.x) * blockDim.x
    ) {
        double sum = 0.0;
        for (std::size_t selected = 0; selected < selected_count; ++selected) {
            const auto update_index = static_cast<std::size_t>(selected_indices[selected]);
            sum += static_cast<double>(resolve_update(pointer_table, update_index)[coordinate]);
        }
        output[coordinate] = static_cast<float>(
            sum / static_cast<double>(selected_count)
        );
    }
}

[[nodiscard]] unsigned int next_power_of_two(std::size_t value) {
    unsigned int result = 1;
    while (result < value) {
        result <<= 1U;
    }
    return result;
}

[[nodiscard]] cudaStream_t decode_stream(std::uintptr_t stream) {
    return reinterpret_cast<cudaStream_t>(stream);
}

}  // namespace

void launch_pairwise_distances(
    std::uintptr_t pointer_table_device,
    std::uintptr_t distances_device,
    std::size_t client_count,
    std::size_t dimension,
    std::uintptr_t stream
) {
    if (pointer_table_device == 0 || distances_device == 0) {
        throw std::invalid_argument("CUDA device pointers must be non-zero");
    }
    if (client_count == 0 || dimension == 0) {
        throw std::invalid_argument("CUDA aggregation requires non-empty updates");
    }
    if (client_count > 65535) {
        throw std::invalid_argument("CUDA pairwise kernel supports at most 65535 clients");
    }

    constexpr unsigned int threads = 256;
    const dim3 grid(
        static_cast<unsigned int>(client_count),
        static_cast<unsigned int>(client_count),
        1
    );
    pairwise_distance_kernel<<<
        grid,
        threads,
        threads * sizeof(double),
        decode_stream(stream)
    >>>(
        reinterpret_cast<const PointerWord*>(pointer_table_device),
        reinterpret_cast<double*>(distances_device),
        client_count,
        dimension
    );
    check_launch("pairwise_distance_kernel");
}

void launch_trimmed_mean(
    std::uintptr_t pointer_table_device,
    std::uintptr_t output_device,
    std::size_t client_count,
    std::size_t dimension,
    float beta,
    std::uintptr_t stream
) {
    if (pointer_table_device == 0 || output_device == 0) {
        throw std::invalid_argument("CUDA device pointers must be non-zero");
    }
    if (client_count == 0 || dimension == 0) {
        throw std::invalid_argument("CUDA aggregation requires non-empty updates");
    }
    if (!std::isfinite(beta) || beta < 0.0F || beta >= 0.5F) {
        throw std::invalid_argument("trim ratio beta must satisfy 0 <= beta < 0.5");
    }
    if (client_count > kMaxTrimmedMeanClients) {
        throw std::invalid_argument("CUDA trimmed mean supports at most 1024 clients");
    }

    const std::size_t trim_count = static_cast<std::size_t>(
        std::floor(static_cast<double>(beta) * static_cast<double>(client_count))
    );
    if (2 * trim_count >= client_count) {
        throw std::invalid_argument("trim ratio removes every model update");
    }

    const unsigned int threads = next_power_of_two(client_count);
    const unsigned int blocks = static_cast<unsigned int>(
        dimension < 65535 ? dimension : 65535
    );
    trimmed_mean_kernel<<<
        blocks,
        threads,
        static_cast<std::size_t>(threads) * sizeof(double),
        decode_stream(stream)
    >>>(
        reinterpret_cast<const PointerWord*>(pointer_table_device),
        reinterpret_cast<float*>(output_device),
        client_count,
        dimension,
        trim_count
    );
    check_launch("trimmed_mean_kernel");
}

void launch_average_selected(
    std::uintptr_t pointer_table_device,
    std::uintptr_t selected_indices_device,
    std::uintptr_t output_device,
    std::size_t selected_count,
    std::size_t dimension,
    std::uintptr_t stream
) {
    if (
        pointer_table_device == 0 ||
        selected_indices_device == 0 ||
        output_device == 0
    ) {
        throw std::invalid_argument("CUDA device pointers must be non-zero");
    }
    if (selected_count == 0 || dimension == 0) {
        throw std::invalid_argument("CUDA selected-average requires non-empty input");
    }

    constexpr unsigned int threads = 256;
    const std::size_t required_blocks = (dimension + threads - 1) / threads;
    const unsigned int blocks = static_cast<unsigned int>(
        required_blocks < 65535 ? required_blocks : 65535
    );
    average_selected_kernel<<<blocks, threads, 0, decode_stream(stream)>>>(
        reinterpret_cast<const PointerWord*>(pointer_table_device),
        reinterpret_cast<const std::int64_t*>(selected_indices_device),
        reinterpret_cast<float*>(output_device),
        selected_count,
        dimension
    );
    check_launch("average_selected_kernel");
}

int runtime_version() {
    int version = 0;
    const cudaError_t status = cudaRuntimeGetVersion(&version);
    if (status != cudaSuccess) {
        throw_cuda_error(status, "cudaRuntimeGetVersion");
    }
    return version;
}

}  // namespace zerotrust::fl::aggregation::cuda
