# Security model

Operate only on authorized offline network evidence. FlowSpectre has no live interception or active scanning capability. It never opens indicator destinations or sends packets. CLI inputs must be regular local files and are not modified. `.gitignore` excludes common capture and log extensions, but operators must review Git status before sharing the repository.

JSON reports can contain sensitive IP addresses, ports, and timing. Store and share them according to the source environment's evidence policy. The report hash is an integrity reference, not chain-of-custody certification. Periodicity and volume findings are heuristics, not validated probabilities or proof of malicious behavior. Unavailable templates and unsupported formats are surfaced explicitly.

Current limitations: no per-user authentication because this milestone has no server; no data retention manager; no PCAPNG or IPv6; no NetFlow sampling adjustment; no deep packet inspection; no live integration validation. Add authentication and audit logging before exposing a persistent API.
