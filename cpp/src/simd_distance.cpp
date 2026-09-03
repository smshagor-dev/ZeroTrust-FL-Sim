#include "simd_distance.hpp"

#include <cstddef>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif

namespace zerotrust::fl::aggregation::detail {
namespace {

using DistanceFn = double (*)(const float*, const float*, std::size_t) noexcept;

[[nodiscard]] double squared_distance_scalar(
    const float* lhs,
    const float* rhs,
    std::size_t size
) noexcept {
    double sum = 0.0;
    for (std::size_t i = 0; i < size; ++i) {
        const double delta = static_cast<double>(lhs[i]) - static_cast<double>(rhs[i]);
        sum += delta * delta;
    }
    return sum;
}

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__x86_64__) || defined(__i386__))
__attribute__((target("avx512f,avx,fma")))
[[nodiscard]] double squared_distance_avx512(
    const float* lhs,
    const float* rhs,
    std::size_t size
) noexcept {
    __m512d accumulator = _mm512_setzero_pd();
    std::size_t i = 0;
    for (; i + 8 <= size; i += 8) {
        const __m256 lhs_f = _mm256_loadu_ps(lhs + i);
        const __m256 rhs_f = _mm256_loadu_ps(rhs + i);
        const __m512d lhs_d = _mm512_cvtps_pd(lhs_f);
        const __m512d rhs_d = _mm512_cvtps_pd(rhs_f);
        const __m512d delta = _mm512_sub_pd(lhs_d, rhs_d);
        accumulator = _mm512_fmadd_pd(delta, delta, accumulator);
    }

    alignas(64) double lanes[8];
    _mm512_store_pd(lanes, accumulator);
    double sum = 0.0;
    for (double lane : lanes) {
        sum += lane;
    }
    for (; i < size; ++i) {
        const double delta = static_cast<double>(lhs[i]) - static_cast<double>(rhs[i]);
        sum += delta * delta;
    }
    return sum;
}

[[nodiscard]] bool avx512_available() noexcept {
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx512f") &&
           __builtin_cpu_supports("avx") &&
           __builtin_cpu_supports("fma");
}
#endif

#if defined(__aarch64__) && defined(__ARM_NEON)
[[nodiscard]] double squared_distance_neon(
    const float* lhs,
    const float* rhs,
    std::size_t size
) noexcept {
    float64x2_t accumulator_lo = vdupq_n_f64(0.0);
    float64x2_t accumulator_hi = vdupq_n_f64(0.0);
    std::size_t i = 0;
    for (; i + 4 <= size; i += 4) {
        const float32x4_t lhs_f = vld1q_f32(lhs + i);
        const float32x4_t rhs_f = vld1q_f32(rhs + i);
        const float32x4_t delta_f = vsubq_f32(lhs_f, rhs_f);
        const float64x2_t delta_lo = vcvt_f64_f32(vget_low_f32(delta_f));
        const float64x2_t delta_hi = vcvt_f64_f32(vget_high_f32(delta_f));
        accumulator_lo = vfmaq_f64(accumulator_lo, delta_lo, delta_lo);
        accumulator_hi = vfmaq_f64(accumulator_hi, delta_hi, delta_hi);
    }

    alignas(16) double lanes_lo[2];
    alignas(16) double lanes_hi[2];
    vst1q_f64(lanes_lo, accumulator_lo);
    vst1q_f64(lanes_hi, accumulator_hi);
    double sum = lanes_lo[0] + lanes_lo[1] + lanes_hi[0] + lanes_hi[1];
    for (; i < size; ++i) {
        const double delta = static_cast<double>(lhs[i]) - static_cast<double>(rhs[i]);
        sum += delta * delta;
    }
    return sum;
}
#endif

struct Dispatch {
    DistanceFn fn;
    const char* name;
};

[[nodiscard]] Dispatch resolve_dispatch() noexcept {
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__x86_64__) || defined(__i386__))
    if (avx512_available()) {
        return {&squared_distance_avx512, "avx512"};
    }
#endif
#if defined(__aarch64__) && defined(__ARM_NEON)
    return {&squared_distance_neon, "neon"};
#else
    return {&squared_distance_scalar, "scalar"};
#endif
}

[[nodiscard]] const Dispatch& dispatch() noexcept {
    static const Dispatch selected = resolve_dispatch();
    return selected;
}

}  // namespace

double squared_euclidean_distance_simd(
    const float* lhs,
    const float* rhs,
    std::size_t size
) noexcept {
    return dispatch().fn(lhs, rhs, size);
}

const char* active_simd_backend() noexcept {
    return dispatch().name;
}

}  // namespace zerotrust::fl::aggregation::detail
