# FlowSpectre

FlowSpectre is an offline, passive flow analysis CLI for authorized network evidence. It reads raw NetFlow v5 datagrams, a fixed-length IPv4 subset of template-based NetFlow v9 and IPFIX, Zeek JSON `conn.log` records, and classic Ethernet/IPv4 PCAP. It normalizes source/destination relationships, summarizes byte and packet counts, and produces explainable volume and periodicity indicators. Findings are investigation cues, not assertions of compromise.

## Run

Python 3.12+ is the only runtime dependency for the current offline engine. From this repository:

```bash
PYTHONPATH=. python3.12 -m flowspectre.cli --format netflow --exporter approved-exporter /path/to/export-1.bin /path/to/export-2.bin > investigation.json
PYTHONPATH=. python3.12 -m flowspectre.cli --format zeek /path/to/authorized-conn.json > investigation.json
PYTHONPATH=. python3.12 -m flowspectre.cli --format pcap /path/to/authorized-capture.pcap > investigation.json
```

Pass raw export **datagrams** for NetFlow/IPFIX, ordered so templates precede records. The `--exporter` value scopes cached templates. The report includes source SHA-256, flow references, normalized records, parse issues, directed relationships, and threshold evidence. The default high-volume threshold is 100,000,000 bytes; set `--volume-threshold` to an approved positive value. No packet capture or network transmission occurs.

## Supported format boundaries

| Source | Implemented | Not covered |
| --- | --- | --- |
| NetFlow v5 | 24-byte header, 48-byte IPv4 records, counters, switched timestamps | Sampling adjustment, live UDP collection |
| NetFlow v9 | Fixed-length template/data sets, standard IPv4/counter/port/protocol fields | Options templates, IPv6, template expiry/withdrawal, unknown enterprise fields |
| IPFIX | Fixed-length standard IPv4 IEs, template sets, enterprise field skip | Variable-length fields, options, IPv6, transport sessions, template withdrawal |
| Zeek | JSON `conn.log` lines and selected counters | TSV logs and broader Zeek schemas |
| PCAP | Classic PCAP, Ethernet, one VLAN tag, IPv4, TCP/UDP ports | PCAPNG, IPv6, other link types, fragment reassembly, full protocol dissection |

The NetFlow v9/IPFIX subset follows [RFC 3954](https://datatracker.ietf.org/doc/html/rfc3954), [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011), and the [IPFIX information model](https://www.iana.org/assignments/ipfix). Zeek fields are based on the [official `conn.log` documentation](https://docs.zeek.org/en/current/reference/logs/conn.html). Unit fixtures validate specific examples only; no live exporter was verified.

Periodicity needs at least five separate flow records to the same destination and port, mean interval 10–3600 seconds, and interval coefficient of variation at most 0.2. The report states the observed values. PCAP packets are aggregated into one flow per five-tuple, so this first release does not infer repeated connections from a PCAP alone. A high-volume pair is any directed pair over the threshold; it is **not** automatically classified as external egress.

Each finding has an explainable 0–100 **triage score** based only on its threshold ratio or interval regularity. These policy points are not calibrated probabilities and have not been validated against benign traffic.

## Validation and roadmap

```bash
python3.12 -m compileall -q flowspectre tests
python3.12 -m unittest discover -s tests -v
```

See [VALIDATION_REPORT.md](VALIDATION_REPORT.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [SECURITY.md](SECURITY.md). The next milestone is a bounded PCAPNG reader and richer template lifecycle tests, followed by a read-only authenticated investigation API and optional persistence when authorized evidence retention requires it. No dashboard or database is implemented in this offline milestone.
