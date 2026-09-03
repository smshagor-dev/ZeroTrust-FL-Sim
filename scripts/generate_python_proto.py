"""Generate Python protobuf and gRPC client modules from proto/fl_service.proto."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from grpc_tools import protoc


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    proto_dir = repository_root / "proto"
    source = proto_dir / "fl_service.proto"
    output_dir = repository_root / "fl" / "zerotrust_fl" / "protocols"
    output_dir.mkdir(parents=True, exist_ok=True)

    result = protoc.main(
        [
            "grpc_tools.protoc",
            f"-I{proto_dir}",
            f"--python_out={output_dir}",
            f"--grpc_python_out={output_dir}",
            str(source),
        ]
    )
    if result != 0:
        return result

    grpc_file = output_dir / "fl_service_pb2_grpc.py"
    text = grpc_file.read_text(encoding="utf-8")
    text = re.sub(
        r"^import fl_service_pb2 as (.+)$",
        r"from . import fl_service_pb2 as \1",
        text,
        flags=re.MULTILINE,
    )
    grpc_file.write_text(text, encoding="utf-8")
    print(f"Generated Python gRPC modules in {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
