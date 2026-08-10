#!/usr/bin/env python3
import argparse
from pathlib import Path

from app.pcap.manifest import build_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the official NTA capture manifest")
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(args.dataset_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    print(manifest.summary.model_dump_json())


if __name__ == "__main__":
    main()
