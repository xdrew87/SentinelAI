# Changelog

All notable changes to SentinelAI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-20

### Added
- Case management module with full investigation lifecycle tracking
- Log investigation with Windows Event Log and syslog parsing
- PCAP analysis via Scapy integration
- Static malware analysis with YARA rule matching
- Memory analysis and artifact extraction
- IOC investigation and correlation engine
- Threat intelligence feed integration and enrichment
- MITRE ATT&CK tactic/technique mapping
- Sigma rule execution against log data
- Chronological timeline reconstruction
- AI-powered executive summary generation (OpenAI, Anthropic, Gemini, Ollama)
- Report export to PDF, DOCX, and HTML
- Encrypted API key and config storage
- Immutable audit log
- Crash reporting with local log capture

### Fixed
- `AttributeError: 'sqlite3.Row' object has no attribute 'get'` in AI summary generation (`modules/reporting.py`)
