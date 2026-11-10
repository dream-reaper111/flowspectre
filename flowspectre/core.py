"""Bounded NetFlow, IPFIX, Zeek and classic-PCAP normalization.

Only fixed-length standard IPv4 fields are decoded from template protocols.
Unsupported records are reported; they are never interpreted as flows.
"""

from __future__ import annotations

import ipaddress
import json
import math
import struct
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT = 512 * 1024 * 1024
MAX_RECORDS = 1_000_000
MAX_PACKET = 262144
V5_HEADER = struct.Struct("!HHIIIIBBH")
V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")


class FlowError(ValueError):
    pass


def utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


@dataclass(frozen=True)
class Flow:
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    packets: int
    bytes: int
    first_seen: str
    last_seen: str
    source_format: str
    reference: str


def _ip(value: bytes | int) -> str:
    return str(ipaddress.IPv4Address(value))


def parse_v5(datagram: bytes, reference: str) -> list[Flow]:
    if len(datagram) < V5_HEADER.size:
        raise FlowError("short NetFlow v5 header")
    version, count, uptime, seconds, nseconds, _sequence, _engine_type, _engine_id, _sampling = V5_HEADER.unpack_from(datagram)
    if version != 5 or count > 30 or len(datagram) != V5_HEADER.size + count * V5_RECORD.size:
        raise FlowError("invalid NetFlow v5 version, count, or length")
    export_time = seconds + nseconds / 1e9
    flows = []
    for i in range(count):
        values = V5_RECORD.unpack_from(datagram, V5_HEADER.size + i * V5_RECORD.size)
        src, dst = values[0], values[1]
        packets, octets, first, last = values[5:9]
        if first > uptime or last > uptime or first > last:
            raise FlowError("NetFlow v5 switched times inconsistent with exporter uptime")
        start = export_time - (uptime - first) / 1000
        end = export_time - (uptime - last) / 1000
        flows.append(Flow(_ip(src), _ip(dst), values[9], values[10], values[13],
                          packets, octets, utc(start), utc(end), "netflow5", f"{reference}#{i}"))
    return flows


class TemplateDecoder:
    """Cache templates per exporter/domain; parse fixed-length standard IPv4 IEs."""

    def __init__(self):
        self.templates: dict[tuple[int, str, int, int], tuple[tuple[int, int, int | None], ...]] = {}

    def parse(self, datagram: bytes, exporter: str, reference: str) -> tuple[list[Flow], list[str]]:
        if len(datagram) < 16:
            raise FlowError("short flow export header")
        version = struct.unpack_from("!H", datagram)[0]
        if version == 9:
            if len(datagram) < 20:
                raise FlowError("short NetFlow v9 header")
            _, _count, uptime, export_seconds, _seq, domain = struct.unpack_from("!HHIIII", datagram)
            header_size = 20
            template_set = 0
            end = len(datagram)
            fmt = "netflow9"
        elif version == 10:
            _, message_length, export_seconds, _seq, domain = struct.unpack_from("!HHIII", datagram)
            if message_length != len(datagram):
                raise FlowError("invalid IPFIX message length")
            uptime = None
            header_size = 16
            template_set = 2
            end = message_length
            fmt = "ipfix"
        else:
            raise FlowError("unsupported flow export version")
        flows: list[Flow] = []
        issues: list[str] = []
        cursor = header_size
        while cursor < end:
            if cursor + 4 > end:
                raise FlowError("truncated set header")
            set_id, set_length = struct.unpack_from("!HH", datagram, cursor)
            if set_length < 4 or cursor + set_length > end:
                raise FlowError("invalid set length")
            body = memoryview(datagram)[cursor + 4:cursor + set_length]
            if set_id == template_set:
                self._templates(body, version, exporter, domain, issues)
            elif set_id >= 256:
                key = (version, exporter, domain, set_id)
                fields = self.templates.get(key)
                if fields is None:
                    issues.append(f"set {set_id}: template unavailable")
                else:
                    record_size = sum(length for _, length, _ in fields)
                    if record_size == 0:
                        issues.append(f"set {set_id}: zero-length template")
                    else:
                        offset = 0
                        while offset + record_size <= len(body):
                            record = body[offset:offset + record_size]
                            flow = self._record(record, fields, version, uptime, export_seconds,
                                                fmt, f"{reference}:set{set_id}:offset{offset}")
                            if flow:
                                flows.append(flow)
                            else:
                                issues.append(f"set {set_id}: required IPv4 fields absent or invalid")
                            offset += record_size
                        if any(body[offset:]) or len(body) - offset > 3:
                            issues.append(f"set {set_id}: trailing bytes not valid padding")
            else:
                issues.append(f"set {set_id}: unsupported options or reserved set")
            cursor += set_length
        return flows, issues

    def _templates(self, body: memoryview, version: int, exporter: str,
                   domain: int, issues: list[str]) -> None:
        offset = 0
        while offset + 4 <= len(body):
            if not any(body[offset:]):
                return
            template_id, field_count = struct.unpack_from("!HH", body, offset)
            offset += 4
            if template_id < 256 or field_count == 0 or field_count > 128:
                raise FlowError("invalid template identifier or field count")
            fields = []
            unsupported = False
            for _ in range(field_count):
                if offset + 4 > len(body):
                    raise FlowError("truncated template field")
                element, length = struct.unpack_from("!HH", body, offset)
                offset += 4
                enterprise = None
                if version == 10 and element & 0x8000:
                    if offset + 4 > len(body):
                        raise FlowError("truncated enterprise element")
                    enterprise = struct.unpack_from("!I", body, offset)[0]
                    offset += 4
                    element &= 0x7fff
                if length in {0, 65535} or length > MAX_PACKET:
                    issues.append(f"template {template_id}: variable or invalid field length unsupported")
                    unsupported = True
                fields.append((element, length, enterprise))
            if fields and not unsupported:
                self.templates[(version, exporter, domain, template_id)] = tuple(fields)
        if any(body[offset:]):
            issues.append("template set has trailing non-padding bytes")

    @staticmethod
    def _record(record: memoryview, fields: tuple[tuple[int, int, int | None], ...],
                version: int, uptime: int | None, export_seconds: int,
                fmt: str, reference: str) -> Flow | None:
        decoded = {}
        offset = 0
        for element, length, enterprise in fields:
            value = bytes(record[offset:offset + length])
            offset += length
            if enterprise is None and element in {1, 2, 4, 7, 8, 11, 12, 21, 22, 150, 151}:
                decoded[element] = value
        if len(decoded.get(8, b"")) != 4 or len(decoded.get(12, b"")) != 4:
            return None
        if not all(1 <= len(decoded.get(key, b"")) <= 8 for key in (1, 2)):
            return None
        number = lambda key: int.from_bytes(decoded[key], "big") if key in decoded else None
        start = end = float(export_seconds)
        if version == 9 and uptime is not None and number(22) is not None and number(21) is not None:
            if number(22) > uptime or number(21) > uptime or number(22) > number(21):
                return None
            start = export_seconds - (uptime - number(22)) / 1000
            end = export_seconds - (uptime - number(21)) / 1000
        if version == 10 and number(150) is not None and number(151) is not None:
            start, end = float(number(150)), float(number(151))
            if start > end:
                return None
        return Flow(_ip(decoded[8]), _ip(decoded[12]), number(7), number(11), number(4),
                    number(2), number(1), utc(start), utc(end), fmt, reference)


def parse_zeek(path: Path) -> tuple[list[Flow], list[str]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise FlowError("Zeek input must be a regular file of at most 512 MiB")
    flows: list[Flow] = []
    issues: list[str] = []
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if number > MAX_RECORDS or len(raw) > MAX_PACKET:
                raise FlowError("Zeek line or record count limit exceeded")
            if not raw.strip() or raw.startswith(b"#"):
                continue
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("not an object")
                src = str(ipaddress.ip_address(row["id.orig_h"]))
                dst = str(ipaddress.ip_address(row["id.resp_h"]))
                ts = float(row["ts"])
                duration = float(row.get("duration") or 0)
                if not math.isfinite(ts) or not math.isfinite(duration) or duration < 0:
                    raise ValueError("invalid timestamp")
                protocol = {"tcp": 6, "udp": 17, "icmp": 1}.get(row.get("proto"))
                src_port = int(row["id.orig_p"]) if row.get("id.orig_p") is not None else None
                dst_port = int(row["id.resp_p"]) if row.get("id.resp_p") is not None else None
                if any(p is not None and not 0 <= p <= 65535 for p in (src_port, dst_port)):
                    raise ValueError("invalid port")
                packets = sum(int(row.get(k) or 0) for k in ("orig_pkts", "resp_pkts"))
                octets = sum(int(row.get(k) or 0) for k in ("orig_ip_bytes", "resp_ip_bytes"))
                if "orig_pkts" not in row and "resp_pkts" not in row:
                    issues.append(f"line {number}: packet counters unavailable; zero recorded")
                if "orig_ip_bytes" not in row and "resp_ip_bytes" not in row:
                    issues.append(f"line {number}: IP byte counters unavailable; zero recorded")
                if packets < 0 or octets < 0:
                    raise ValueError("negative counter")
                flows.append(Flow(src, dst, src_port, dst_port, protocol, packets, octets,
                                  utc(ts), utc(ts + duration), "zeek-json", f"line:{number}"))
            except (ValueError, KeyError, TypeError, OverflowError):
                issues.append(f"line {number}: unsupported or invalid conn record")
    return flows, issues


def parse_pcap(path: Path) -> tuple[list[Flow], list[str]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise FlowError("PCAP input must be a regular file of at most 512 MiB")
    flows = {}
    issues: list[str] = []
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise FlowError("short classic PCAP header")
        magic = header[:4]
        variants = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                    b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if magic not in variants:
            raise FlowError("unsupported PCAP magic or PCAPNG")
        endian, divisor = variants[magic]
        _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", header[4:])
        if linktype != 1:
            raise FlowError("only Ethernet link type is supported")
        for index in range(MAX_RECORDS):
            record_header = stream.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                raise FlowError("truncated PCAP packet header")
            seconds, subsecond, captured, _original = struct.unpack(endian + "IIII", record_header)
            if captured > MAX_PACKET or subsecond >= divisor:
                raise FlowError("invalid PCAP packet length or timestamp")
            frame = stream.read(captured)
            if len(frame) != captured:
                raise FlowError("truncated PCAP packet")
            if len(frame) < 34:
                issues.append(f"packet {index}: short Ethernet/IP frame")
                continue
            ethertype = int.from_bytes(frame[12:14], "big")
            offset = 14
            if ethertype == 0x8100 and len(frame) >= 38:
                ethertype = int.from_bytes(frame[16:18], "big")
                offset = 18
            if ethertype != 0x0800:
                continue
            ip = frame[offset:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                issues.append(f"packet {index}: invalid IPv4 header")
                continue
            ihl = (ip[0] & 15) * 4
            total_length = int.from_bytes(ip[2:4], "big")
            if ihl < 20 or len(ip) < ihl or total_length < ihl or total_length > len(ip):
                issues.append(f"packet {index}: truncated IPv4 packet")
                continue
            if int.from_bytes(ip[6:8], "big") & 0x1fff:
                issues.append(f"packet {index}: non-initial fragment skipped")
                continue
            protocol = ip[9]
            src, dst = _ip(ip[12:16]), _ip(ip[16:20])
            sport = dport = None
            if protocol in (6, 17):
                if len(ip) < ihl + 4:
                    issues.append(f"packet {index}: short transport header")
                    continue
                sport, dport = struct.unpack_from("!HH", ip, ihl)
            key = (src, dst, sport, dport, protocol)
            observed = seconds + subsecond / divisor
            if key not in flows:
                flows[key] = [0, 0, observed, observed, index]
            item = flows[key]
            item[0] += 1
            item[1] += len(frame)
            item[2] = min(item[2], observed)
            item[3] = max(item[3], observed)
        else:
            if stream.read(1):
                raise FlowError("PCAP exceeds one million packets")
    result = [Flow(*key, data[0], data[1], utc(data[2]), utc(data[3]), "pcap-ethernet-ipv4",
                   f"first-packet:{data[4]}") for key, data in flows.items()]
    return result, issues


def investigate(flows: list[Flow], issues: list[str], source_sha256: str,
                volume_threshold: int = 100_000_000) -> dict:
    if volume_threshold < 1:
        raise FlowError("volume threshold must be positive")
    relationships = defaultdict(lambda: {"flows": 0, "bytes": 0, "packets": 0})
    observations = defaultdict(list)
    for flow in flows:
        pair = (flow.source_ip, flow.destination_ip)
        relationships[pair]["flows"] += 1
        relationships[pair]["bytes"] += flow.bytes
        relationships[pair]["packets"] += flow.packets
        key = (flow.source_ip, flow.destination_ip, flow.destination_port, flow.protocol)
        observations[key].append(datetime.fromisoformat(flow.first_seen).timestamp())
    findings = []
    for (src, dst), value in relationships.items():
        if value["bytes"] >= volume_threshold:
            ratio = value["bytes"] / volume_threshold
            findings.append({"type": "high_volume_pair", "source_ip": src,
                             "destination_ip": dst, "observed_bytes": value["bytes"],
                             "threshold_bytes": volume_threshold,
                             "triage_score": 70 if ratio >= 4 else 50,
                             "score_factors": [{"factor": "directed_pair_bytes_over_threshold",
                                                "observed_ratio": round(ratio, 3),
                                                "points": 70 if ratio >= 4 else 50}],
                             "interpretation": "volume threshold exceeded; destination and intent require analyst review"})
    for (src, dst, port, protocol), times in observations.items():
        if len(times) < 5:
            continue
        ordered = sorted(times)
        intervals = [b - a for a, b in zip(ordered, ordered[1:])]
        mean = sum(intervals) / len(intervals)
        if 10 <= mean <= 3600:
            cv = math.sqrt(sum((n - mean) ** 2 for n in intervals) / len(intervals)) / mean
            if cv <= 0.2:
                findings.append({"type": "periodic_connection_indicator", "source_ip": src,
                                 "destination_ip": dst, "destination_port": port, "protocol": protocol,
                                 "observations": len(times), "mean_interval_seconds": round(mean, 3),
                                 "interval_cv": round(cv, 4),
                                 "triage_score": 65 if cv <= 0.1 else 50,
                                 "score_factors": [{"factor": "repeated_regular_intervals",
                                                    "observations": len(times), "interval_cv": round(cv, 4),
                                                    "points": 65 if cv <= 0.1 else 50}],
                                 "interpretation": "regular timing is an anomaly indicator, not proof of beaconing"})
    return {"schema_version": 1, "source_sha256": source_sha256,
            "flow_count": len(flows), "total_bytes": sum(f.bytes for f in flows),
            "total_packets": sum(f.packets for f in flows),
            "relationships": [{"source_ip": src, "destination_ip": dst, **value}
                              for (src, dst), value in sorted(relationships.items())],
            "findings": findings, "issues": issues,
            "flows": [asdict(flow) for flow in flows]}
