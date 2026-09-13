# Intel Lookup

A small command-line tool that looks up an IP address, domain, or file hash
against threat intelligence APIs and prints a clean summary.

- **IP addresses** are checked against [AbuseIPDB](https://www.abuseipdb.com/) (API v2).
- **Domains and file hashes (MD5/SHA1/SHA256)** are checked against [VirusTotal](https://www.virustotal.com/) (API v3).

The indicator type is auto-detected from what you pass in — no flags needed.
Every lookup is logged locally so you can search back through what you've
already checked without burning another API call.

## Why I built this

As a SOC analyst, a huge chunk of alert triage comes down to the same
repetitive question: "have I seen this IP/domain/hash before, and is it
known-bad?" That usually means pivoting between AbuseIPDB, VirusTotal, and a
notes doc for every single indicator in an alert — slow, easy to lose track
of, and hard to search back through later.

This tool collapses that into one command: paste in an indicator, get a
clean summary back, and have it automatically logged with an optional note
(ticket number, case name, whatever) so past enrichment is searchable
instead of scattered across browser tabs. It's a small project, but it's
built around the actual shape of threat intel enrichment work — auto-detect
the indicator type, hit the right source, log it, make it searchable.

## Setup

1. Clone the repo:

   ```bash
   git clone <your-repo-url>
   cd intel_lookup
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create your own `.env` file from the example and add your API keys:

   ```bash
   cp .env.example .env
   ```

   Then edit `.env`:

   ```
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ```

   - Get a free AbuseIPDB key: https://www.abuseipdb.com/account/api
   - Get a free VirusTotal key: https://www.virustotal.com/gui/my-apikey

   `.env` is git-ignored, so your keys are never committed.

## Usage

```bash
python intel_lookup.py 8.8.8.8
python intel_lookup.py example.com
python intel_lookup.py 44d88612fea8a8f36de82e1278abb02f
```

### History (Phase 2)

Every lookup is automatically recorded in a local SQLite database
(`history.db`, created next to the script). Each row stores the indicator,
its type (IP/domain/hash), the source used (AbuseIPDB/VirusTotal), a result
summary, a UTC timestamp, and an optional note.

Attach a note with `--note`:

```bash
python3 intel_lookup.py 8.8.8.8 --note "MyDFIR Lab 3"
```

If `--note` is omitted, the note is stored as blank. `history.db` is
git-ignored and never committed.

### Searching history (Phase 3)

Query your saved lookup history instead of doing a live API lookup:

```bash
# Partial match on indicator
python3 intel_lookup.py --search "8.8.8.8"

# Partial match on note text
python3 intel_lookup.py --search-note "MyDFIR"
```

Results print as a table (indicator, type, source, timestamp, note), newest
first. If nothing matches, the tool prints "No results found." instead of
an error.

### Example output

```
Indicator: 8.8.8.8 (IP address)
Source: AbuseIPDB
----------------------------------------
Abuse Confidence Score : 0/100
Country                : US
ISP                    : Google LLC
Domain                 : google.com
Usage Type             : Data Center/Web Hosting/Transit
Total Reports          : 12
Last Reported          : 2026-08-01T12:00:00+00:00
Is Whitelisted         : True
```

## Error handling

The tool exits with a non-zero status and prints a message to stderr when:

- An API key is missing from `.env`
- The indicator type can't be determined (not a valid IP, domain, or hash)
- The API rate limit is hit (HTTP 429)
- The API key is invalid (HTTP 401)
- The indicator isn't found in the vendor's database (HTTP 404)
- There's no internet connection or the request times out

## Notes

- Phase 1: single indicator, on-demand lookups. No caching, batching,
  or additional enrichment sources yet.
- Phase 2: every lookup is logged to a local `history.db` SQLite database,
  with an optional `--note` for labeling entries.
- Phase 3: `--search`/`--search-note` query that history without hitting
  any API.
