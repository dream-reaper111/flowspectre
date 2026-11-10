"""Offline authorized flow evidence analysis; no packet capture or network activity."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from .core import FlowError, TemplateDecoder, investigate, parse_pcap, parse_v5, parse_zeek


def analyze(paths: list[Path], source_format: str, exporter: str, volume_threshold: int) -> dict:
    if source_format != "netflow" and len(paths) != 1:
        raise FlowError("Zeek and PCAP analysis each require one input")
    digest = hashlib.sha256()
    flows = []
    issues = []
    decoder = TemplateDecoder()
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
            raise FlowError("input must be a regular file of at most 512 MiB")
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        if source_format == "zeek":
            new, notes = parse_zeek(path)
        elif source_format == "pcap":
            new, notes = parse_pcap(path)
        else:
            if path.stat().st_size > 65535:
                raise FlowError("raw flow export datagram exceeds 65535 bytes")
            raw = path.read_bytes()
            if len(raw) < 2:
                raise FlowError("short flow export datagram")
            version = struct.unpack_from("!H", raw)[0]
            if version == 5:
                new, notes = parse_v5(raw, path.name), []
            else:
                new, notes = decoder.parse(raw, exporter, path.name)
        flows.extend(new)
        issues.extend(notes)
        if len(flows) > 1_000_000:
            raise FlowError("aggregate flow limit exceeded")
    return investigate(flows, issues, digest.hexdigest(), volume_threshold)


def main() -> None:
    parser = argparse.ArgumentParser(prog="flowspectre")
    parser.add_argument("--format", choices=("netflow", "zeek", "pcap"), required=True)
    parser.add_argument("--exporter", help="NetFlow/IPFIX exporter identity; required for template scope")
    parser.add_argument("--volume-threshold", type=int, default=100_000_000)
    parser.add_argument("paths", nargs="+", type=Path, help="authorized offline input files")
    args = parser.parse_args()
    if args.format == "netflow" and not args.exporter:
        parser.error("--exporter is required for NetFlow/IPFIX")
    try:
        result = analyze(args.paths, args.format, args.exporter or "", args.volume_threshold)
    except (FlowError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
