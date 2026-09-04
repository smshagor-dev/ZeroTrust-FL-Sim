from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext


class CMakeExtension(Extension):
    def __init__(self, name: str, source_dir: str = "cpp") -> None:
        super().__init__(name, sources=[])
        self.source_dir = str(Path(source_dir).resolve())


class CMakeBuild(build_ext):
    def build_extension(self, ext: CMakeExtension) -> None:
        extension_path = Path(self.get_ext_fullpath(ext.name)).resolve()
        output_dir = extension_path.parent
        build_type = "Debug" if self.debug else "Release"
        build_temp = Path(self.build_temp) / ext.name
        build_temp.mkdir(parents=True, exist_ok=True)

        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={output_dir}{os.sep}",
            f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={output_dir}{os.sep}",
            f"-DPython_EXECUTABLE={Path(sys.executable).resolve()}",
            f"-DCMAKE_BUILD_TYPE={build_type}",
            f"-DZTFL_NATIVE_ARCH={os.getenv('ZTFL_NATIVE_ARCH', 'OFF')}",
            f"-DZTFL_ENABLE_OPENMP={os.getenv('ZTFL_ENABLE_OPENMP', 'ON')}",
            f"-DZTFL_ENABLE_CKKS={os.getenv('ZTFL_ENABLE_CKKS', 'ON')}",
            f"-DZTFL_ENABLE_CUDA={os.getenv('ZTFL_ENABLE_CUDA', 'AUTO')}",
        ]
        build_args = ["--config", build_type]

        if platform.system() == "Windows":
            cmake_args.extend(
                [
                    f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{build_type.upper()}={output_dir}{os.sep}",
                    f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY_{build_type.upper()}={output_dir}{os.sep}",
                ]
            )
            if self.plat_name and "CMAKE_GENERATOR" not in os.environ:
                cmake_args.extend(["-A", "x64" if "64" in self.plat_name else "Win32"])
        elif "CMAKE_BUILD_PARALLEL_LEVEL" not in os.environ and getattr(self, "parallel", None):
            build_args.extend(["-j", str(self.parallel)])

        subprocess.run(
            ["cmake", ext.source_dir, *cmake_args],
            cwd=build_temp,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", ".", *build_args],
            cwd=build_temp,
            check=True,
        )


setup(
    name="zerotrust-fl-sim",
    version="0.4.0",
    description="Zero-trust federated learning simulation runtime",
    author="Shahanur Islam Shagor",
    url="https://github.com/smshagor-dev/ZeroTrust-FL-Sim",
    project_urls={
        "Source": "https://github.com/smshagor-dev/ZeroTrust-FL-Sim",
        "Issues": "https://github.com/smshagor-dev/ZeroTrust-FL-Sim/issues",
        "Documentation": "https://github.com/smshagor-dev/ZeroTrust-FL-Sim#documentation",
        "Security": "https://github.com/smshagor-dev/ZeroTrust-FL-Sim/security/policy",
    },
    license="Apache-2.0",
    license_files=["LICENSE"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: C++",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
    python_requires=">=3.12",
    package_dir={"": "fl"},
    packages=find_packages(where="fl"),
    install_requires=[
        "torch==2.14.0",
        "numpy>=2.3,<3.0",
        "grpcio==1.83.1",
        "protobuf>=7.35,<8.0",
        "psutil>=7,<8",
        "opentelemetry-api==1.44.0",
        "opentelemetry-sdk==1.44.0",
        "opentelemetry-exporter-otlp-proto-grpc==1.44.0",
        "opentelemetry-instrumentation-grpc==0.65b0",
        "prometheus-client>=0.22,<1",
    ],
    extras_require={
        "vision": ["torchvision==0.29.0"],
        "proto": ["grpcio-tools==1.83.1"],
        "benchmark": ["cryptography>=45,<50", "matplotlib>=3.10,<4"],
        "tenseal": ["tenseal==0.3.17"],
    },
    ext_modules=[CMakeExtension("zerotrust_fl_cpp")],
    cmdclass={"build_ext": CMakeBuild},
    zip_safe=False,
)
