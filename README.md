# SentinelAI

**Commercial-Grade DFIR & Threat Intelligence Desktop Application**

SentinelAI is a PySide6-based desktop tool for Digital Forensics and Incident Response (DFIR), integrating AI-powered analysis, threat intelligence, and reporting into a single workflow.
---


## ScreenShot

<img width="1406" height="934" alt="Screenshot_2026-07-19_23-13-11" src="https://github.com/user-attachments/assets/a22ecb14-9047-411a-96be-fc982c009948" />

---

## Features

- **Case Management** — Track investigations from triage to closure
- **Log Investigation** — Parse and flag Windows Event Logs, syslogs, and more
- **PCAP Analysis** — Network traffic inspection via Scapy
- **Malware Analysis** — Static analysis with YARA rule matching
- **Memory Analysis** — Process and artifact extraction from memory dumps
- **IOC Investigation** — Indicator of Compromise lookup and correlation
- **Threat Intelligence** — External feed integration and enrichment
- **MITRE ATT&CK** — Tactic/technique mapping for observed behaviors
- **Sigma Rules** — Detection rule execution against log data
- **Timeline** — Chronological event reconstruction
- **AI Summary** — Executive summary generation via OpenAI, Anthropic, Gemini, or local Ollama
- **Reporting** — Export cases to PDF, DOCX, or HTML

---

## Requirements

- Python 3.10+
- See [`requirements.txt`](requirements.txt) for all dependencies

Key dependencies:

| Package | Purpose |
|---|---|
| PySide6 | Desktop UI framework |
| cryptography | Encrypted config/secret storage |
| reportlab / python-docx | Report generation |
| yara-python | YARA rule scanning |
| scapy | PCAP analysis |
| python-evtx | Windows Event Log parsing |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/xdrew87/SentinelAI.git
cd SentinelAI

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

> **Note:** `yara-python` and `scapy` may require system-level libraries.  
> On Debian/Ubuntu: `sudo apt install libssl-dev libpcap-dev`

---

## AI Configuration

SentinelAI supports multiple AI providers for automated analysis. Configure your provider and API key in **Settings → AI** within the application. Keys are stored encrypted and never written in plain text.

Supported providers:
- OpenAI (`gpt-4o`, etc.)
- Anthropic (Claude)
- Google Gemini
- Ollama (local, no key required)

---

## Project Structure

```
sentinelai/
├── main.py              # Application entry point
├── requirements.txt
├── core/                # Core services
│   ├── config.py        # Encrypted config and app-data paths
│   ├── database.py      # SQLite schema and query helpers
│   ├── ai_client.py     # Unified AI provider abstraction
│   ├── audit_log.py     # Immutable audit trail
│   ├── crash_log.py     # Unhandled exception capture
│   └── ...
├── modules/             # Feature modules (each is a QWidget panel)
│   ├── case_management.py
│   ├── reporting.py
│   ├── log_investigation.py
│   └── ...
└── ui/                  # Main window, theme, shared widgets
    ├── main_window.py
    └── theme.py
```

---

## License

Proprietary — All rights reserved.
