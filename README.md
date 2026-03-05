# 🕵 Dark Web Monitor

A cybersecurity tool that monitors breach databases, paste sites, and threat intelligence feeds for leaked company credentials, emails, domains, and sensitive keywords.

---

## 📁 Project Structure

```
darkweb-monitor/
├── backend/
│   ├── monitor.py        ← Core scan engine (all scanners)
│   └── server.py         ← Flask REST API
├── frontend/
│   └── index.html        ← Web dashboard (noir/terminal aesthetic)
├── config/
│   └── config.json       ← Your monitored assets & API keys
├── reports/              ← Auto-saved scan reports (JSON + CSV)
├── cli_scan.py           ← Run scans from terminal
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### Step 1 — Install
```bash
pip install -r requirements.txt
```

### Step 2 — Configure your assets
Edit `config/config.json`:
```json
{
  "hibp_api_key":        "your-key-here",
  "monitored_emails":   ["admin@company.com", "ceo@company.com"],
  "monitored_domains":  ["company.com"],
  "monitored_keywords": ["Company Inc", "internal-codename"]
}
```

### Step 3 — Run

**Terminal CLI:**
```bash
python cli_scan.py
python cli_scan.py --verbose        # Show full details
python cli_scan.py --severity high  # Filter by severity
python cli_scan.py --new-only       # New findings only
```

**Web Dashboard:**
```bash
cd backend && python server.py
# Open frontend/index.html in browser
```

---

## 🔍 Data Sources

| Scanner | What It Checks | Key Required? |
|---|---|---|
| **HaveIBeenPwned** | Email breaches across 700+ known breaches | Yes (free) |
| **PasteSites** | Pastebin & paste mirrors for keyword/email leaks | No |
| **Dehashed** | Leaked credential database (email+password pairs) | Yes (paid) |
| **ThreatIntel** | CISA known exploited CVEs + breach RSS feeds | No |

### Getting Free API Keys
- **HIBP** (recommended): https://haveibeenpwned.com/API/Key — ~$4/mo, unlimited lookups
- **Dehashed**: https://dehashed.com — credential leak search

---

## 🚨 Severity Levels

| Level | Meaning | Action |
|---|---|---|
| 🔴 Critical | Password/credential found in breach | Rotate immediately |
| 🟠 High | Email in breach, sensitive data exposed | Review & rotate |
| 🟡 Medium | Keyword/domain found in paste | Investigate |
| 🟢 Low | Informational match | Monitor |

---

## 📊 Reports

Every scan auto-saves to `reports/`:
- `scan_YYYYMMDD_HHMMSS.json` — Full report
- `latest.json` — Always the most recent scan

---

## 🏢 Use Cases

- **Daily breach monitoring** for employee emails
- **Domain monitoring** — detect if your domain appears in paste dumps
- **Credential leak detection** — identify exposed passwords before attackers exploit them
- **Compliance** — evidence of proactive monitoring for SOC2, ISO 27001, GDPR
- **Executive protection** — monitor C-suite personal emails

---

## ⚠️ Legal Notice

This tool queries public threat intelligence APIs and breach notification services only. It does not access the dark web directly. Always use ethically and only on assets you own or have permission to monitor.
