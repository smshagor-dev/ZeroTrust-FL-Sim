# Native Byzantine-Robust Aggregation

The native aggregation extension exposes CPU-optimized C++20 implementations of Krum, Multi-Krum, adaptive coordinate-wise trimmed mean, and coordinate-wise median to the Python federated learning runtime.

The Python module is named `zerotrust_fl_cpp`. Native computation runs without the Python GIL.

## Algorithms

### Krum and Multi-Krum

For each client update, the implementation computes squared Euclidean distances to every other client update. The Krum score is the sum of the `n-f-2` smallest peer distances, where `n` is the number of clients and `f` is the assumed Byzantine-client bound.

The implementation requires:

```text
n >= 2*f + 3
1 <= k <= n-f-2
```

`k=1` performs classic Krum. Larger values select the `k` lowest-scoring updates and return their coordinate-wise mean.

### Adaptive trimmed mean

For each model coordinate, the implementation sorts the client values and removes:

```text
floor(beta * n)
```

values from each tail. `beta` must satisfy `0 <= beta < 0.5`.

### Coordinate-wise median

Each model coordinate is aggregated independently. Odd client counts use the middle order statistic. Even client counts use the arithmetic mean of the two middle values.

## Numerical and input handling

- Native input type is contiguous `float32`.
- Pairwise Krum distances and aggregation sums use `double` accumulation.
- NaN and infinity values are rejected before aggregation.
- All updates must contain the same number of elements and the pybind interface additionally requires equal shapes.
- Results preserve the input NumPy shape.

CPU contiguous `torch.float32` tensors become NumPy views without an additional data copy. Non-contiguous tensors, other floating dtypes, and accelerator tensors are converted to contiguous host-side `float32` buffers before native aggregation.

## Parallel execution

OpenMP is enabled when supported by the compiler. Parallel work covers:

- finite-value validation
- Krum pairwise distance rows
- Krum score calculation
- selected-model averaging
- trimmed-mean coordinates
- median coordinates

The pairwise distance inner loop also uses an OpenMP SIMD reduction when OpenMP is available.

If OpenMP is unavailable, the same implementation builds and runs serially.

## Build for local development

Create and activate the Python environment first, then install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Build and install the Python package in editable mode:

```bash
pip install -e .
```

Verify the extension:

```bash
python -c "import zerotrust_fl_cpp as native; print(native.__version__, native.openmp_enabled)"
```

## Direct CMake build

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release --parallel
```

The standalone CMake build writes the module to `cpp/build/python/` by default.

For a portable binary that is not tied to the build machine CPU instruction set:

```bash
cmake -S cpp -B cpp/build -DZTFL_NATIVE_ARCH=OFF
```

The editable package build accepts the same setting through the environment:

Linux or macOS:

```bash
ZTFL_NATIVE_ARCH=OFF pip install -e .
```

Windows PowerShell:

```powershell
$env:ZTFL_NATIVE_ARCH="OFF"
pip install -e .
```

OpenMP can be disabled with `ZTFL_ENABLE_OPENMP=OFF`.

## PyTorch usage

```python
import torch
from zerotrust_fl.aggregators import CppByzantineAggregator

aggregator = CppByzantineAggregator()
updates = [torch.randn(100_000) for _ in range(10)]

krum = aggregator.krum(updates, f=2, k=1)
multi_krum = aggregator.krum(updates, f=2, k=3)
trimmed = aggregator.trimmed_mean(updates, beta=0.2)
median = aggregator.median(updates)
```

## Tests

Run correctness and adversarial-stability tests:

```bash
pytest tests/test_cpp_aggregator.py -q
```

Run the optional one-million-parameter native-vs-pure-Python micro-benchmark:

Linux or macOS:

```bash
ZTFL_RUN_PERF=1 pytest tests/test_cpp_aggregator.py -m performance -s
```

Windows PowerShell:

```powershell
$env:ZTFL_RUN_PERF="1"
pytest tests/test_cpp_aggregator.py -m performance -s
```

The performance test is opt-in because execution time varies significantly by CPU, compiler, OpenMP runtime, and active system load.
