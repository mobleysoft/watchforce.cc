#!/usr/bin/env python3
"""
Refresh mccomb_sdn_data.json from the live U.S. Treasury OFAC SDN list.

MCCOMB Entity Screening's real value proposition is screening against real,
current sanctions data. mccomb_sdn_data.json started as a one-time manual
snapshot (fetched 2026-08-29, 19,321 entries) with no refresh mechanism -
found stale during the 2026-09-26 depth audit (the live list had already
grown to 19,391 entries, 70 more than the shipped snapshot).

Usage: python3 refresh_sdn_data.py
Fetches https://www.treasury.gov/ofac/downloads/sdn.csv (public, no key
required, follows Treasury's redirect to sanctionslistservice.ofac.treas.gov)
and overwrites mccomb_sdn_data.json in place, in the exact same schema the
site's JS already expects: {id, name, type, program, remarks}, with the
CSV's "-0-" placeholder normalized to null. Also updates the "fetched
<date>" note in mccomb.html's footnote so the page never quietly claims a
staler date than what's actually on disk.

Re-run this periodically (a human/audit deciding cadence) rather than
treating the 2026-08-29 snapshot as a one-time event - a compliance tool
whose "due diligence" data source silently ages is a real, ongoing gap,
not a single bug to fix once.
"""
import csv
import io
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone

SDN_CSV_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
DATA_PATH = "mccomb_sdn_data.json"
HTML_PATH = "mccomb.html"

# OFAC's published SDN.CSV column order (no header row):
# ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type,
# Tonnage, GRT, Vess_flag, Vess_owner, Remarks
COL_ID, COL_NAME, COL_TYPE, COL_PROGRAM = 0, 1, 2, 3
COL_REMARKS = 11


def clean(value):
    value = (value or "").strip()
    return None if value in ("", "-0-") else value


def fetch_csv_text():
    req = urllib.request.Request(SDN_CSV_URL, headers={"User-Agent": "watchforce.cc MCCOMB/1.0 (+sdn refresh)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    # OFAC's CSV is Latin-1 encoded, not UTF-8 (accented names would raise otherwise).
    return raw.decode("latin-1")


def parse_rows(csv_text):
    rows = []
    reader = csv.reader(io.StringIO(csv_text))
    for row in reader:
        if len(row) < 12:
            continue
        rows.append({
            "id": clean(row[COL_ID]),
            "name": clean(row[COL_NAME]),
            "type": clean(row[COL_TYPE]).lower() if clean(row[COL_TYPE]) else None,
            "program": clean(row[COL_PROGRAM]),
            "remarks": clean(row[COL_REMARKS]),
        })
    return rows


def main():
    csv_text = fetch_csv_text()
    rows = parse_rows(csv_text)
    if len(rows) < 15000:
        print(f"Refusing to write: parsed only {len(rows)} rows, suspiciously low for a real SDN fetch - source may have changed format", file=sys.stderr)
        sys.exit(1)

    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(rows, f)

    fetch_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        html = f.read()
    new_html, n = re.subn(
        r"[\d,]+ entries, fetched \d{4}-\d{2}-\d{2}",
        f"{len(rows):,} entries, fetched {fetch_date}",
        html,
    )
    if n:
        with open(HTML_PATH, "w", encoding="utf-8") as f:
            f.write(new_html)
    else:
        print(f"WARNING: no 'N entries, fetched <date>' footnote pattern found in {HTML_PATH} - left unchanged", file=sys.stderr)

    print(f"Wrote {len(rows)} entries to {DATA_PATH}, footnote updated to fetched {fetch_date}" if n else f"Wrote {len(rows)} entries to {DATA_PATH}")


if __name__ == "__main__":
    main()
