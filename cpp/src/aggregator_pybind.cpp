#include "byzantine_aggregator.hpp"

#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace py = pybind11;
namespace aggregation = zerotrust::fl::aggregation;

namespace {

using FloatArray = py::array_t<float, py::array::c_style | py::array::forcecast>;

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

}  // namespace

PYBIND11_MODULE(zerotrust_fl_cpp, module) {
    module.doc() = "C++20 Byzantine-robust aggregation primitives for ZeroTrust-FL-Sim";
    module.attr("__version__") = "0.2.0";
#ifdef ZTFL_HAS_OPENMP
    module.attr("openmp_enabled") = true;
#else
    module.attr("openmp_enabled") = false;
#endif

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
}
