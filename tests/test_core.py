import json
import struct
import tempfile
import unittest
from pathlib import Path

from flowspectre.cli import analyze
from flowspectre.core import Flow, FlowError, TemplateDecoder, investigate, parse_pcap, parse_v5, parse_zeek


def sample_v5():
    header = struct.pack("!HHIIIIBBH", 5, 1, 100000, 1700000000, 0, 1, 0, 0, 0)
    record = struct.pack("!IIIHHIIIIHHBBBBHHBBH", 0xc0000201, 0xc6336402, 0, 0, 0,
                         2, 1000, 90000, 95000, 1234, 443, 0, 0, 6, 0, 0, 0, 0, 0, 0)
    return header + record


def sample_template(version):
    fields = [(8, 4), (12, 4), (1, 4), (2, 4), (7, 2), (11, 2)]
    body = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *field) for field in fields)
    template = struct.pack("!HH", 0 if version == 9 else 2, len(body) + 4) + body
    data = struct.pack("!IIIIHH", 0xc0000201, 0xc6336402, 1000, 2, 1234, 443)
    data_set = struct.pack("!HH", 256, len(data) + 4) + data
    if version == 9:
        return struct.pack("!HHIIII", 9, 2, 100000, 1700000000, 0, 1) + template + data_set
    return struct.pack("!HHIII", 10, 16 + len(template) + len(data_set), 1700000000, 0, 1) + template + data_set


class FlowTests(unittest.TestCase):
    def test_v5_and_invalid_length(self):
        flows = parse_v5(sample_v5(), "fixture")
        self.assertEqual((flows[0].source_ip, flows[0].destination_port, flows[0].bytes),
                         ("192.0.2.1", 443, 1000))
        with self.assertRaises(FlowError):
            parse_v5(sample_v5()[:-1], "fixture")

    def test_v9_and_ipfix_templates(self):
        decoder = TemplateDecoder()
        for version in (9, 10):
            flows, issues = decoder.parse(sample_template(version), "exporter-1", "fixture")
            self.assertEqual(issues, [])
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0].packets, 2)

    def test_missing_template_is_reported(self):
        datagram = sample_template(10)
        only_data = datagram[:16] + datagram[16 + 32:]
        only_data = only_data[:2] + struct.pack("!H", len(only_data)) + only_data[4:]
        flows, issues = TemplateDecoder().parse(only_data, "exporter-1", "fixture")
        self.assertEqual(flows, [])
        self.assertIn("template unavailable", issues[0])

    def test_zeek_json(self):
        row = {"ts": 1700000000.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.2",
               "id.orig_p": 1234, "id.resp_p": 443, "proto": "tcp", "duration": 2.5,
               "orig_pkts": 2, "resp_pkts": 1, "orig_ip_bytes": 120, "resp_ip_bytes": 80}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "conn.json"
            path.write_text(json.dumps(row) + "\n")
            flows, issues = parse_zeek(path)
        self.assertEqual(issues, [])
        self.assertEqual((flows[0].bytes, flows[0].packets), (200, 3))

    def test_classic_pcap_ipv4_udp(self):
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ip = bytes.fromhex("4500001c0000000040110000c0000201c6336402")
        udp = struct.pack("!HHHH", 1234, 53, 8, 0)
        frame = ethernet + ip + udp
        raw = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        raw += struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.pcap"
            path.write_bytes(raw)
            flows, issues = parse_pcap(path)
        self.assertEqual(issues, [])
        self.assertEqual((flows[0].destination_port, flows[0].bytes), (53, len(frame)))

    def test_periodicity_is_labelled_indicator(self):
        flows = [Flow("192.0.2.1", "198.51.100.2", 1234, 443, 6, 1, 100,
                      f"2026-01-01T00:{minute:02d}:00+00:00",
                      f"2026-01-01T00:{minute:02d}:01+00:00", "fixture", str(i))
                 for i, minute in enumerate((0, 1, 2, 3, 4))]
        report = investigate(flows, [], "0" * 64)
        self.assertEqual(report["findings"][0]["type"], "periodic_connection_indicator")
        self.assertIn("not proof", report["findings"][0]["interpretation"])
        self.assertEqual(report["findings"][0]["score_factors"][0]["factor"], "repeated_regular_intervals")

    def test_cli_analysis_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.bin"
            path.write_bytes(sample_v5())
            report = analyze([path], "netflow", "exporter-1", 10000)
        self.assertEqual(report["flow_count"], 1)
        self.assertEqual(len(report["source_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
