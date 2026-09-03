# SIMD and CUDA aggregation acceleration

ZeroTrust-FL-Sim provides two native acceleration layers for Byzantine-robust aggregation:

- CPU SIMD dispatch for the Krum/Multi-Krum squared-distance hot path.
- Optional CUDA kernels that consume CUDA-resident PyTorch tensor storage directly.

## CPU SIMD dispatch

The C++20 core resolves the distance implementation once per process:

| Architecture | Backend | Activation |
| --- | --- | --- |
| x86/x86-64 with GCC or Clang | AVX-512F + FMA | Runtime CPU feature detection |
| AArch64 | ARM NEON/Advanced SIMD | Compile-time AArch64 NEON path |
| Other/unsupported CPUs | Scalar | Automatic fallback |

The AVX-512 and NEON paths widen `float32` inputs to `float64` for distance accumulation, matching the numerical strategy used by the portable implementation. OpenMP still parallelizes client-pair work; SIMD accelerates the inner parameter loop.

Runtime inspection:

```bash
python -c "import zerotrust_fl_cpp as n; print(n.simd_backend, n.openmp_enabled)"
```

## CUDA build

CUDA is optional. CMake accepts `ZTFL_ENABLE_CUDA=AUTO|ON|OFF`; the Python build defaults to `AUTO`.

```bash
ZTFL_ENABLE_CUDA=ON ZTFL_NATIVE_ARCH=OFF python -m pip install -e .
python -c "import zerotrust_fl_cpp as n; print(n.cuda_enabled, n.cuda_runtime_version())"
```

`ON` fails configuration if no CUDA compiler is available. `AUTO` enables CUDA only when CMake detects a working CUDA compiler/toolkit. CPU-only builds keep the same public CPU API.

## Device-resident PyTorch path

```python
import torch
from zerotrust_fl.aggregators import CudaByzantineAggregator

updates = [torch.randn(1_000_000, device="cuda", dtype=torch.float32) for _ in range(7)]
aggregator = CudaByzantineAggregator()

krum = aggregator.krum(updates, f=1, k=2)
trimmed = aggregator.trimmed_mean(updates, beta=0.2)
```

The CUDA wrapper requires every update to be:

- `torch.float32`;
- contiguous;
- on the same CUDA device; and
- identical in shape.

Those constraints are deliberate: satisfying them lets the native extension use each tensor's existing `data_ptr()` instead of staging the model update through CPU memory or creating a second contiguous model-sized buffer.

Only a small device-side table of update pointers is allocated. Krum creates an `n x n` `float64` distance matrix; its size depends on the client count, not the model parameter count.

## Krum CUDA mechanics

For updates `W_i in R^d`, the CUDA kernel assigns client pairs to blocks and computes

```text
D_ij = ||W_i - W_j||_2^2
```

using a block-level `float64` reduction. PyTorch then performs the small `n x n` nearest-neighbor/score selection on the same CUDA stream. A second native kernel averages only the selected Krum candidates directly from the original update pointers.

No model-sized host transfer occurs.

## Trimmed-mean CUDA mechanics

The trimmed-mean kernel assigns coordinates to blocks. For each coordinate, one block loads the client values into shared memory, performs an in-block bitonic sort, removes `floor(beta*n)` values from both tails, and reduces the retained values.

The current custom kernel supports at most 1024 clients, matching the maximum CUDA thread block size used by the shared-memory sort. This bound applies to client count, not parameter count.

## CUDA IPC and zero-copy semantics

ZeroTrust-FL-Sim intentionally does **not** export raw `cudaIpcMemHandle_t` values from arbitrary PyTorch allocations. A PyTorch tensor may point inside a larger caching-allocator block, so manually exporting/importing that pointer can violate allocator ownership and lifetime rules.

For cross-process workers, use PyTorch's supported CUDA tensor sharing through `torch.multiprocessing` with `spawn` or `forkserver`. PyTorch performs CUDA IPC mapping and returns a valid tensor in the receiving process. `CudaByzantineAggregator` then consumes that mapped tensor's `data_ptr()` directly, so the model payload remains zero-copy after the IPC mapping.

The producing process must remain alive for as long as receiving processes use the shared CUDA tensor, in accordance with PyTorch CUDA-sharing semantics.

## Stream ordering

Native kernels are launched on `torch.cuda.current_stream(device)`. The pointer table, PyTorch `topk` operations, and output tensors therefore participate in the same stream dependency chain without an unconditional device synchronization.

`validate_finite=False` is the default for the CUDA backend so very large updates do not incur a second full model scan before aggregation. Set `validate_finite=True` when strict finite-value validation is required; this adds a GPU reduction and host-visible scalar check for each update.

## Complexity

For `n` clients and `d` parameters:

| Path | Time | Extra memory |
| --- | --- | --- |
| CPU Krum + OpenMP + SIMD | `O(n^2 d / P)` idealized | `O(n^2)` distance matrix |
| CUDA Krum distance matrix | `O(n^2 d / GPU parallelism)` | `O(n^2)` GPU distance matrix |
| CPU trimmed mean | `O(d n log n / P)` | per-thread `O(n)` scratch |
| CUDA trimmed mean | `O(d log^2 n)` block-sort steps | `O(n)` shared memory per active block |

The practical bottleneck for billion-parameter models is memory bandwidth and the total bytes represented by all client updates. CUDA removes repeated host-device staging from the aggregation hot path, but it does not make `n*d` model storage disappear.

## Benchmark

```bash
python benchmarks/benchmark_acceleration.py --method krum --clients 7 --parameters 1000000
python benchmarks/benchmark_acceleration.py --method trimmed_mean --clients 10 --parameters 1000000
```

Run large experiments only after checking device/host memory capacity. A billion `float32` parameters require about 4 GB per update before optimizer state, model state, distance output, or framework overhead.
