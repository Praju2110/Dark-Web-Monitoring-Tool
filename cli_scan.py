#!/usr/bin/env python3
"""
Dark Web Monitor — CLI Mode
Usage:
  python cli_scan.py                  # Run scan, print results
  python cli_scan.py --verbose        # Show all findings
  python cli_scan.py --json           # Raw JSON output
  python cli_scan.py --severity high  # Filter by severity
"""

import argparse
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from monitor import DarkWebMonitor, CONFIG_PATH

R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
PURPLE = "\033[95m"
GRAY = "\033[90m"
GREEN_BG = "\033[42m\033[30m"

SEV_COLOR = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN, "info": CYAN}
SEV_ICON  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}


def c(text, col): return f"{col}{text}{R}"
def b(text): return f"{BOLD}{text}{R}"


def banner():
    print(f"""
{CYAN}╔═══════════════════════════════════════════════════════════╗
║  🕵   D A R K W E B   M O N I T O R   v1.0                ║
║       Threat Intelligence & Breach Detection               ║
╚═══════════════════════════════════════════════════════════╝{R}
""")


def print_finding(f, verbose=False):
    sev = f["severity"]
    col = SEV_COLOR.get(sev, R)
    icon = SEV_ICON.get(sev, "⚪")
    new_tag = f" {GREEN_BG} NEW {R}" if f.get("is_new") else ""

    print(f"\n  {icon} {b(c(f['title'], col))}{new_tag}")
    print(f"     Source : {c(f['source'], CYAN)}   Asset: {f['asset']}")
    if f.get("breach_date"):
        print(f"     Breach : {f['breach_date']}")
    print(f"     Time   : {f['discovered_at'][:19]}")

    if verbose and f.get("description"):
        print(f"     Desc   : {GRAY}{f['description'][:200]}{R}")

    if verbose and f.get("data"):
        for k, v in list(f["data"].items())[:4]:
            if v:
                val_str = ", ".join(v[:5]) if isinstance(v, list) else str(v)[:80]
                print(f"     {k:15}: {GRAY}{val_str}{R}")


def main():
    parser = argparse.ArgumentParser(description="Dark Web Monitor CLI")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", "-j", action="store_true")
    parser.add_argument("--severity", "-s", choices=["critical","high","medium","low","info"])
    parser.add_argument("--new-only", "-n", action="store_true")
    args = parser.parse_args()

    banner()

    monitor = DarkWebMonitor(CONFIG_PATH)

    # Warn if no assets configured
    emails   = monitor.config.get("monitored_emails", [])
    domains  = monitor.config.get("monitored_domains", [])
    keywords = monitor.config.get("monitored_keywords", [])

    if not (emails or domains or keywords):
        print(f"{YELLOW}⚠  No assets configured. Edit config/config.json first.{R}")
        print(f"""
  Add your targets:
  {{
    "monitored_emails":   ["you@company.com"],
    "monitored_domains":  ["company.com"],
    "monitored_keywords": ["Company Name"],
    "hibp_api_key":       "your-key-here"
  }}
""")

    print(f"{GRAY}[*] Running scan...{R}\n")
    report = monitor.run_scan()

    if args.json:
        print(json.dumps(report, indent=2))
        return

    s = report["summary"]
    print(b("═══ Scan Summary ═══════════════════════════════════════"))
    print(f"  Scanned At : {report['scan_time'][:19]}")
    print(f"  Emails     : {', '.join(emails) or 'none'}")
    print(f"  Domains    : {', '.join(domains) or 'none'}")
    print(f"  Keywords   : {', '.join(keywords) or 'none'}")
    print()
    print(f"  Total Findings  : {b(report['total_findings'])}")
    print(f"  New This Scan   : {c(str(report['new_findings']), GREEN)}")
    print(f"  {c('Critical', RED)}         : {c(str(s['critical']), RED)}")
    print(f"  {c('High', ORANGE)}             : {c(str(s['high']), ORANGE)}")
    print(f"  {c('Medium', YELLOW)}           : {c(str(s['medium']), YELLOW)}")
    print(f"  {c('Low', GREEN)}              : {c(str(s['low']), GREEN)}")
    print()

    findings = report["findings"]
    if args.severity:
        findings = [f for f in findings if f["severity"] == args.severity]
    if args.new_only:
        findings = [f for f in findings if f.get("is_new")]

    if not findings:
        print(f"  {c('✓ No findings match filter.', GREEN)}")
    else:
        print(b("═══ Findings ════════════════════════════════════════════"))
        for f in sorted(findings, key=lambda x: ["critical","high","medium","low","info"].index(x["severity"])):
            print_finding(f, verbose=args.verbose)

    print()
    if s["critical"]:
        print(c(f"⚠  ALERT: {s['critical']} CRITICAL finding(s) detected! Immediate action required.", RED + BOLD))
    elif s["high"]:
        print(c(f"!  WARNING: {s['high']} HIGH-severity finding(s). Review recommended.", ORANGE + BOLD))
    else:
        print(c("✓  No critical threats detected in this scan.", GREEN))
    print()


if __name__ == "__main__":
    main()
