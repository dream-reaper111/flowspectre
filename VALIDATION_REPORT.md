# FlowSpectre validation report

Date: 2026-11-09. Scope: new FlowSpectre repository. All parser inputs used for testing were isolated synthetic fixtures. No operational network telemetry was imported or presented as a detection.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed: `python3 -m compileall -q flowspectre tests` |
| `python3 -m unittest discover -s tests -v` | 7 passed, 0 failed, 0 skipped |
| NetFlow v5 parser | Tested against one bounded fixture and a truncated-record rejection |
| NetFlow v9 / IPFIX template parser | Tested with fixed-length IPv4 template+data fixtures and a missing-template issue |
| Zeek JSON parser | Tested against one isolated conn record |
| Classic PCAP parser | Tested against one isolated Ethernet/IPv4/UDP frame |
| Periodicity and report export | Unit tested with isolated flows; no false-positive study performed |
| Real exporters, authorized captures, PCAPNG, IPv6 | Not verified or not implemented |
| Ruff, pytest, Docker, API, database, dashboard | Ruff/pytest unavailable in documented environment; other components not part of this offline milestone |

Next: test against sanitized authorized captures from more than one exporter, add malformed-packet and template lifecycle tests, and measure bounded processing performance. Do not report broad protocol support from these fixtures.
