#include "byzantine_aggregator.hpp"
#ifdef ZTFL_HAS_CKKS
#include "ckks_secure_aggregation.hpp"
#endif
#ifdef ZTFL_HAS_CUDA
#include "cuda_aggregation.hpp"
#endif

#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;
namespace aggregation = zerotrust::fl::aggregation;
#ifdef ZTFL_HAS_CKKS
namespace privacy = zerotrust::fl::privacy;
#endif
#ifdef ZTFL_HAS_CUDA
namespace cuda_aggregation = zerotrust::fl::aggregation::cuda;
#endif

namespace {

using FloatArray = py::array_t<float, py::array::c_style | py::array::forcecast>;
using DoubleArray = py::array_t<double, py::array::c_style | py::array::forcecast>;

struct PreparedUpdates {
    std::vector<FloatArray> arrays;
    std::vector<aggregation::UpdateView> views;
    std::vector<py::ssize_t> shape;
};

PreparedUpdates prepare_updates(const std::vector<FloatArray>& updates) {
    if (updates.empty()) {
        throw std::invalid_argument("at least one model update is required");
    }

    PreparedUpdates prepared;
    prepared.arrays = updates;

    const py::buffer_info first = prepared.arrays.front().request();
    if (first.size <= 0) {
        throw std::invalid_argument("model updates must not be empty");
    }
    prepared.shape.assign(first.shape.begin(), first.shape.end());
    prepared.views.reserve(prepared.arrays.size());

    for (std::size_t i = 0; i < prepared.arrays.size(); ++i) {
        const py::buffer_info info = prepared.arrays[i].request();
        if (
            info.ndim != first.ndim ||
            !std::equal(info.shape.begin(), info.shape.end(), first.shape.begin())
        ) {
            throw std::invalid_argument("all model updates must have the same shape");
        }
        prepared.views.push_back({
            static_cast<const float*>(info.ptr),
            static_cast<std::size_t>(info.size),
        });
    }

    return prepared;
}

py::array_t<float> vector_to_numpy(
    std::vector<float>&& values,
    const std::vector<py::ssize_t>& shape
) {
    auto storage = std::make_unique<std::vector<float>>(std::move(values));
    auto* raw_storage = storage.release();
    py::capsule owner(raw_storage, [](void* pointer) {
        delete static_cast<std::vector<float>*>(pointer);
    });

    std::vector<py::ssize_t> strides(
        shape.size(),
        static_cast<py::ssize_t>(sizeof(float))
    );
    if (!shape.empty()) {
        for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(shape.size()) - 2; i >= 0; --i) {
            strides[static_cast<std::size_t>(i)] =
                strides[static_cast<std::size_t>(i + 1)] *
                shape[static_cast<std::size_t>(i + 1)];
        }
    }

    return py::array_t<float>(shape, strides, raw_storage->data(), owner);
}

py::array_t<float> krum_binding(
    const std::vector<FloatArray>& updates,
    int f,
    int k
) {
    if (f < 0) {
        throw std::invalid_argument("Byzantine count f must be non-negative");
    }
    if (k <= 0) {
        throw std::invalid_argument("candidate count k must be positive");
    }

    PreparedUpdates prepared = prepare_updates(updates);
    std::vector<float> result;
    {
        py::gil_scoped_release release;
        result = aggregation::krum_aggregate(
            prepared.views,
            static_cast<std::size_t>(f),
            static_cast<std::size_t>(k)
        );
    }
    return vector_to_numpy(std::move(result), prepared.shape);
}

py::array_t<float> trimmed_mean_binding(
    const std::vector<FloatArray>& updates,
    float beta
) {
    PreparedUpdates prepared = prepare_updates(updates);
    std::vector<float> result;
    {
        py::gil_scoped_release release;
        result = aggregation::trimmed_mean_aggregate(prepared.views, beta);
    }
    return vector_to_numpy(std::move(result), prepared.shape);
}

py::array_t<float> median_binding(const std::vector<FloatArray>& updates) {
    PreparedUpdates prepared = prepare_updates(updates);
    std::vector<float> result;
    {
        py::gil_scoped_release release;
        result = aggregation::median_aggregate(prepared.views);
    }
    return vector_to_numpy(std::move(result), prepared.shape);
}

#ifdef ZTFL_HAS_CKKS
std::vector<double> flatten_double_array(const DoubleArray& values) {
    const py::buffer_info info = values.request();
    if (info.size <= 0) {
        throw std::invalid_argument("CKKS plaintext vector must not be empty");
    }
    const auto* ptr = static_cast<const double*>(info.ptr);
    return std::vector<double>(ptr, ptr + info.size);
}

py::array_t<double> double_vector_to_numpy(std::vector<double>&& values) {
    auto storage = std::make_unique<std::vector<double>>(std::move(values));
    auto* raw_storage = storage.release();
    py::capsule owner(raw_storage, [](void* pointer) {
        delete static_cast<std::vector<double>*>(pointer);
    });
    return py::array_t<double>(
        {static_cast<py::ssize_t>(raw_storage->size())},
        {static_cast<py::ssize_t>(sizeof(double))},
        raw_storage->data(),
        owner
    );
}
#endif

}  // namespace

PYBIND11_MODULE(zerotrust_fl_cpp, module) {
    module.doc() = "C++20 robust and privacy-preserving aggregation primitives for ZeroTrust-FL-Sim";
    module.attr("__version__") = "0.4.0";
#ifdef ZTFL_HAS_OPENMP
    module.attr("openmp_enabled") = true;
#else
    module.attr("openmp_enabled") = false;
#endif
#ifdef ZTFL_HAS_CKKS
    module.attr("ckks_enabled") = true;
#else
    module.attr("ckks_enabled") = false;
#endif
#ifdef ZTFL_HAS_CUDA
    module.attr("cuda_enabled") = true;
    module.attr("cuda_trimmed_mean_max_clients") = cuda_aggregation::kMaxTrimmedMeanClients;
#else
    module.attr("cuda_enabled") = false;
    module.attr("cuda_trimmed_mean_max_clients") = 0;
#endif
    module.attr("simd_backend") = aggregation::simd_backend();

    module.def(
        "krum_aggregate",
        &krum_binding,
        py::arg("updates"),
        py::arg("f"),
        py::arg("k") = 1,
        R"doc(
Aggregate model updates using Krum or Multi-Krum.

Krum scores each update by summing its n-f-2 nearest squared Euclidean
neighbor distances. The k lowest-scoring updates are selected and averaged.
Use k=1 for classic Krum.
)doc"
    );

    module.def(
        "trimmed_mean_aggregate",
        &trimmed_mean_binding,
        py::arg("updates"),
        py::arg("beta"),
        R"doc(
Compute a coordinate-wise adaptive trimmed mean.

For n updates, floor(beta*n) values are removed from both tails for each
coordinate before averaging the retained values.
)doc"
    );

    module.def(
        "median_aggregate",
        &median_binding,
        py::arg("updates"),
        "Compute the coordinate-wise median of model updates."
    );

#ifdef ZTFL_HAS_CUDA
    module.def(
        "cuda_runtime_version",
        &cuda_aggregation::runtime_version,
        "Return the linked CUDA Runtime version as an integer."
    );

    module.def(
        "_cuda_pairwise_distances",
        [](std::uintptr_t pointer_table_device,
           std::uintptr_t distances_device,
           std::size_t client_count,
           std::size_t dimension,
           std::uintptr_t stream) {
            cuda_aggregation::launch_pairwise_distances(
                pointer_table_device,
                distances_device,
                client_count,
                dimension,
                stream
            );
        },
        py::arg("pointer_table_device"),
        py::arg("distances_device"),
        py::arg("client_count"),
        py::arg("dimension"),
        py::arg("stream") = 0,
        "Internal raw-pointer CUDA pairwise-distance launcher."
    );

    module.def(
        "_cuda_trimmed_mean",
        [](std::uintptr_t pointer_table_device,
           std::uintptr_t output_device,
           std::size_t client_count,
           std::size_t dimension,
           float beta,
           std::uintptr_t stream) {
            cuda_aggregation::launch_trimmed_mean(
                pointer_table_device,
                output_device,
                client_count,
                dimension,
                beta,
                stream
            );
        },
        py::arg("pointer_table_device"),
        py::arg("output_device"),
        py::arg("client_count"),
        py::arg("dimension"),
        py::arg("beta"),
        py::arg("stream") = 0,
        "Internal raw-pointer CUDA trimmed-mean launcher."
    );

    module.def(
        "_cuda_average_selected",
        [](std::uintptr_t pointer_table_device,
           std::uintptr_t selected_indices_device,
           std::uintptr_t output_device,
           std::size_t selected_count,
           std::size_t dimension,
           std::uintptr_t stream) {
            cuda_aggregation::launch_average_selected(
                pointer_table_device,
                selected_indices_device,
                output_device,
                selected_count,
                dimension,
                stream
            );
        },
        py::arg("pointer_table_device"),
        py::arg("selected_indices_device"),
        py::arg("output_device"),
        py::arg("selected_count"),
        py::arg("dimension"),
        py::arg("stream") = 0,
        "Internal raw-pointer CUDA selected-update averaging launcher."
    );
#endif

#ifdef ZTFL_HAS_CKKS
    module.def(
        "ckks_generate_key_material",
        [](std::size_t poly_modulus_degree, const std::vector<int>& coeff_modulus_bits, int scale_bits) {
            const auto material = privacy::generate_ckks_key_material(
                poly_modulus_degree,
                coeff_modulus_bits,
                scale_bits
            );
            py::dict result;
            result["parameters"] = py::bytes(material.parameters);
            result["public_key"] = py::bytes(material.public_key);
            result["secret_key"] = py::bytes(material.secret_key);
            result["slot_count"] = material.slot_count;
            result["scale_bits"] = material.scale_bits;
            return result;
        },
        py::arg("poly_modulus_degree") = 8192,
        py::arg("coeff_modulus_bits") = std::vector<int>{60, 40, 40, 60},
        py::arg("scale_bits") = 40,
        "Generate CKKS parameters plus public/secret key material."
    );

    module.def(
        "ckks_encrypt",
        [](const DoubleArray& values, py::bytes parameters, py::bytes public_key, int scale_bits) {
            const std::vector<double> plaintext = flatten_double_array(values);
            const std::string parameter_blob = static_cast<std::string>(parameters);
            const std::string public_key_blob = static_cast<std::string>(public_key);
            std::vector<std::string> result;
            {
                py::gil_scoped_release release;
                result = privacy::ckks_encrypt(
                    plaintext,
                    parameter_blob,
                    public_key_blob,
                    scale_bits
                );
            }
            py::list output;
            for (const auto& chunk : result) {
                output.append(py::bytes(chunk));
            }
            return output;
        },
        py::arg("values"),
        py::arg("parameters"),
        py::arg("public_key"),
        py::arg("scale_bits") = 40,
        "Encrypt a flat vector into one or more CKKS ciphertext chunks."
    );

    module.def(
        "ckks_add",
        [](const std::vector<std::vector<std::string>>& encrypted_updates, py::bytes parameters) {
            const std::string parameter_blob = static_cast<std::string>(parameters);
            std::vector<std::string> result;
            {
                py::gil_scoped_release release;
                result = privacy::ckks_add_ciphertext_sets(
                    encrypted_updates,
                    parameter_blob
                );
            }
            py::list output;
            for (const auto& chunk : result) {
                output.append(py::bytes(chunk));
            }
            return output;
        },
        py::arg("encrypted_updates"),
        py::arg("parameters"),
        "Homomorphically sum encrypted model updates without a secret key."
    );

    module.def(
        "ckks_decrypt",
        [](const std::vector<std::string>& ciphertexts,
           py::bytes parameters,
           py::bytes secret_key,
           std::size_t original_size) {
            const std::string parameter_blob = static_cast<std::string>(parameters);
            const std::string secret_key_blob = static_cast<std::string>(secret_key);
            std::vector<double> result;
            {
                py::gil_scoped_release release;
                result = privacy::ckks_decrypt(
                    ciphertexts,
                    parameter_blob,
                    secret_key_blob,
                    original_size
                );
            }
            return double_vector_to_numpy(std::move(result));
        },
        py::arg("ciphertexts"),
        py::arg("parameters"),
        py::arg("secret_key"),
        py::arg("original_size"),
        "Decrypt an aggregated CKKS ciphertext vector."
    );
#endif
}
