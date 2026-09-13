#!/usr/bin/env python3
"""Personal threat intel lookup CLI.

Usage:
    python intel_lookup.py <ip|domain|hash>
"""

import argparse
import datetime
import ipaddress
import os
import re
import sqlite3
import sys

import requests
from dotenv import load_dotenv

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.db")

HASH_PATTERNS = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class LookupError(Exception):
    """Raised for expected, user-facing failures."""


def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            summary TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def log_lookup(
    conn: sqlite3.Connection,
    indicator: str,
    kind: str,
    source: str,
    summary: str,
    note: str,
) -> None:
    conn.execute(
        """
        INSERT INTO history (indicator, type, source, summary, note, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            indicator,
            kind,
            source,
            summary,
            note or "",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def detect_indicator_type(value: str) -> str:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[A-Fa-f0-9]+", value) and len(value) in HASH_PATTERNS:
        return "hash"

    if DOMAIN_RE.match(value):
        return "domain"

    raise LookupError(
        f"Could not determine indicator type for '{value}'. "
        "Expected an IP address, domain name, or MD5/SHA1/SHA256 hash."
    )


def _request(method: str, url: str, **kwargs) -> requests.Response:
    try:
        response = requests.request(method, url, timeout=15, **kwargs)
    except requests.exceptions.ConnectionError as exc:
        raise LookupError(
            "Could not reach the API. Check your internet connection."
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise LookupError("The request timed out. Try again later.") from exc
    except requests.exceptions.RequestException as exc:
        raise LookupError(f"Request failed: {exc}") from exc

    if response.status_code == 401:
        raise LookupError("Invalid or missing API key. Check your .env file.")
    if response.status_code == 429:
        raise LookupError("Rate limit hit. Wait a bit before trying again.")
    if response.status_code == 404:
        raise LookupError("Indicator not found in the vendor's database.")
    if not response.ok:
        raise LookupError(
            f"API request failed with status {response.status_code}: {response.text[:200]}"
        )

    return response


def lookup_ip(ip: str, api_key: str) -> dict:
    if not api_key:
        raise LookupError(
            "ABUSEIPDB_API_KEY is not set. Add it to your .env file."
        )

    response = _request(
        "GET",
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
    )
    return response.json().get("data", {})


def lookup_virustotal(indicator: str, kind: str, api_key: str) -> dict:
    if not api_key:
        raise LookupError(
            "VIRUSTOTAL_API_KEY is not set. Add it to your .env file."
        )

    endpoint = "domains" if kind == "domain" else "files"
    response = _request(
        "GET",
        f"{VT_BASE_URL}/{endpoint}/{indicator}",
        headers={"x-apikey": api_key},
    )
    return response.json().get("data", {})


def build_ip_summary(data: dict) -> str:
    score = data.get("abuseConfidenceScore", "N/A")
    reports = data.get("totalReports", 0)
    country = data.get("countryCode", "N/A")
    return f"Abuse Score: {score}/100 | Reports: {reports} | Country: {country}"


def build_vt_summary(data: dict) -> str:
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    return f"Malicious: {malicious} | Suspicious: {suspicious} | Total Engines: {total}"


def print_ip_summary(ip: str, data: dict) -> None:
    print(f"\nIndicator: {ip} (IP address)")
    print("Source: AbuseIPDB")
    print("-" * 40)
    print(f"Abuse Confidence Score : {data.get('abuseConfidenceScore', 'N/A')}/100")
    print(f"Country                : {data.get('countryCode', 'N/A')}")
    print(f"ISP                    : {data.get('isp', 'N/A')}")
    print(f"Domain                 : {data.get('domain', 'N/A')}")
    print(f"Usage Type             : {data.get('usageType', 'N/A')}")
    print(f"Total Reports          : {data.get('totalReports', 0)}")
    print(f"Last Reported          : {data.get('lastReportedAt', 'Never')}")
    print(f"Is Whitelisted         : {data.get('isWhitelisted', False)}")


def print_vt_summary(indicator: str, kind: str, data: dict) -> None:
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    print(f"\nIndicator: {indicator} ({kind})")
    print("Source: VirusTotal")
    print("-" * 40)
    print(f"Detection Ratio        : {malicious + suspicious}/{total}")
    print(f"  Malicious            : {malicious}")
    print(f"  Suspicious           : {suspicious}")
    print(f"  Harmless             : {stats.get('harmless', 0)}")
    print(f"  Undetected           : {stats.get('undetected', 0)}")

    last_analysis = attrs.get("last_analysis_date")
    if last_analysis:
        last_analysis = datetime.datetime.fromtimestamp(
            last_analysis, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"Last Analysis Date     : {last_analysis or 'N/A'}")

    if kind == "domain":
        print(f"Country                : {attrs.get('country', 'N/A')}")
        print(f"Registrar              : {attrs.get('registrar', 'N/A')}")
        print(f"Reputation             : {attrs.get('reputation', 'N/A')}")
    else:
        print(f"File Type              : {attrs.get('type_description', 'N/A')}")
        print(f"File Size              : {attrs.get('size', 'N/A')} bytes")
        names = attrs.get("names") or []
        print(f"Known Names            : {', '.join(names[:3]) if names else 'N/A'}")
        print(f"Reputation             : {attrs.get('reputation', 'N/A')}")


def run(indicator: str, note: str = "") -> int:
    load_dotenv()

    try:
        kind = detect_indicator_type(indicator)

        if kind == "ip":
            source = "AbuseIPDB"
            api_key = os.getenv("ABUSEIPDB_API_KEY")
            data = lookup_ip(indicator, api_key)
            print_ip_summary(indicator, data)
            summary = build_ip_summary(data)
        else:
            source = "VirusTotal"
            api_key = os.getenv("VIRUSTOTAL_API_KEY")
            data = lookup_virustotal(indicator, kind, api_key)
            print_vt_summary(indicator, kind, data)
            summary = build_vt_summary(data)

        conn = init_db()
        try:
            log_lookup(conn, indicator, kind, source, summary, note)
        finally:
            conn.close()

        note_suffix = f" (note: {note})" if note else ""
        print(f"\nSaved to history.db{note_suffix}")

    except LookupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


def query_history(
    conn: sqlite3.Connection,
    indicator_query: str = "",
    note_query: str = "",
) -> list:
    conditions = []
    params = []

    if indicator_query:
        conditions.append("indicator LIKE ?")
        params.append(f"%{indicator_query}%")
    if note_query:
        conditions.append("note LIKE ?")
        params.append(f"%{note_query}%")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = (
        f"SELECT indicator, type, source, timestamp, note FROM history "
        f"{where} ORDER BY timestamp DESC"
    )
    return conn.execute(sql, params).fetchall()


def print_history_table(rows: list) -> None:
    headers = ["INDICATOR", "TYPE", "SOURCE", "TIMESTAMP", "NOTE"]
    widths = [
        max(len(headers[i]), max(len(str(row[i])) for row in rows))
        for i in range(len(headers))
    ]

    def format_row(values) -> str:
        return "  ".join(str(v).ljust(w) for v, w in zip(values, widths))

    print(format_row(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(format_row(row))


def search_history(indicator_query: str = "", note_query: str = "") -> int:
    conn = init_db()
    try:
        rows = query_history(conn, indicator_query, note_query)
    finally:
        conn.close()

    if not rows:
        print("No results found.")
        return 0

    print_history_table(rows)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up an IP, domain, or file hash against threat intel APIs."
    )
    parser.add_argument(
        "indicator",
        nargs="?",
        help="IP address, domain name, or file hash (MD5/SHA1/SHA256)",
    )
    parser.add_argument(
        "--note",
        default="",
        help="Optional note to store with this lookup in history.db",
    )
    parser.add_argument(
        "--search",
        metavar="TEXT",
        help="Search lookup history by indicator (partial match), instead of doing a live lookup",
    )
    parser.add_argument(
        "--search-note",
        metavar="TEXT",
        help="Search lookup history by note text (partial match), instead of doing a live lookup",
    )
    args = parser.parse_args()

    if args.search or args.search_note:
        sys.exit(search_history(args.search or "", args.search_note or ""))

    if not args.indicator:
        parser.error("an indicator is required unless --search or --search-note is used")

    sys.exit(run(args.indicator, args.note))


if __name__ == "__main__":
    main()
