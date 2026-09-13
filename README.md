Intel Lookup
A small command-line tool that looks up an IP address, domain, or file hash
against threat intelligence APIs and prints a clean summary.
IP addresses are checked against AbuseIPDB (https://www.abuseipdb.com/) (API v2).
Domains and file hashes (MD5/SHA1/SHA256) are checked against VirusTotal (https://www.virustotal.com/) (API v3).
The indicator type is auto-detected from what you pass in — no flags needed.
Every lookup is logged locally so you can search back through what you've
already checked without burning another API call.
Why I built this
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
Setup
Clone the repo:
git clone https://github.com/a-herrera21/intel-lookup.git
cd intel-lookup
Install dependencies:
pip install -r requirements.txt
Create your own .env file from the example and add your API keys:
cp .env.example .env
Then edit .env:
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
Get a free AbuseIPDB key: https://www.abuseipdb.com/account/api
Get a free VirusTotal key: https://www.virustotal.com/gui/my-apikey
.env is git-ignored, so your keys are never committed.
Usage
python intel_lookup.py 8.8.8.8
python intel_lookup.py example.com
python intel_lookup.py 44d88612fea8a8f36de82e1278abb02f
History (Phase 2)
Every lookup is automatically recorded in a local SQLite database
(history.db, created next to the script). Each row stores the indicator,
its type (IP/domain/hash), the source used (AbuseIPDB/VirusTotal), a result
summary, a UTC timestamp, and an optional note.
Attach a note with --note:
python3 intel_lookup.py 8.8.8.8 --note "MyDFIR Lab 3"
If --note is omitted, the note is stored as blank. history.db is
git-ignored and never committed.
Searching history (Phase 3)
Query your saved lookup history instead of doing a live API lookup:
# Partial match on indicator
python3 intel_lookup.py --search "8.8.8.8"

# Partial match on note text
python3 intel_lookup.py --search-note "MyDFIR"
Results print as a table (indicator, type, source, timestamp, note), newest
first. If nothing matches, the tool prints "No results found." instead of
an error.
Example output
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
Error handling
The tool exits with a non-zero status and prints a message to stderr when:
An API key is missing from .env
The indicator type can't be determined (not a valid IP, domain, or hash)
The API rate limit is hit (HTTP 429)
The API key is invalid (HTTP 401)
The indicator isn't found in the vendor's database (HTTP 404)
There's no internet connection or the request times out
Notes
Phase 1: single indicator, on-demand lookups. No caching, batching,
or additional enrichment sources yet.
Phase 2: every lookup is logged to a local history.db SQLite database,
with an optional --note for labeling entries.
Phase 3: --search/--search-note query that history without hitting
any API.
Build log
Real steps taken to build this, including the mistakes I ran into and how
I fixed them. Screenshots are from actual runs against live API data, not
mocked output.
Phase 1 — Core lookup tool
Built with a single prompt to Claude Code specifying the exact behavior:
auto-detect IP vs. domain vs. hash, query AbuseIPDB for IPs and VirusTotal
for domains/hashes using keys from .env (via python-dotenv), print a
clean summary, and handle errors gracefully (missing key, rate limit,
invalid indicator, no internet).
Installed dependencies and double-checked they actually landed:
![Installing dependencies](screenshots/Screenshot%202026-09-12%20152623.png)
Tested a live IP lookup against AbuseIPDB:
![Successful IP lookup via AbuseIPDB](screenshots/Screenshot%202026-09-12%20154516.png)
Tested a live domain lookup against VirusTotal:
![Successful domain lookup via VirusTotal](screenshots/Screenshot%202026-09-12%20160205.png)
Phase 2 — Local history database
Added SQLite logging for every lookup, plus an optional --note flag.
Mistake I hit: the first version of --note didn't actually work —
passing --note "test entry" on the command line failed instead of saving
the note. I reported the exact error back to Claude Code and it fixed the
argument parsing. Confirmed the fix worked, history.db was created
correctly, and (just as important) confirmed history.db was not
showing up in git status — meaning .gitignore was already excluding it
before any accidental commit could happen.
![--note flag working after the fix](screenshots/Screenshot%202026-09-12%20204757.png)
Phase 3 — Search history
Added --search (by indicator, partial match) and --search-note (by note
text, partial match). Tested three cases in one pass: a known IP, a known
note, and a bogus indicator that shouldn't exist — confirming the tool
prints "No results found" instead of crashing on a miss.
![Search results: IP match, note match, and no-match all handled correctly](screenshots/Screenshot%202026-09-12%20211159.png)
Security/hygiene pass before publishing
Before pushing this repo public, I had Claude Code run a dedicated
hygiene check: confirm .env and history.db are excluded from git,
scan for any hardcoded secrets or API keys anywhere in the code, confirm
error messages never print raw API keys, and trim requirements.txt down
to only what's actually used.
Verified manually as well:
git status
confirmed .env and history.db never appeared as trackable/untracked
files.
grep -ri "abuseipdb_api_key\|virustotal_api_key" *.py
confirmed the code only ever references the key variable names, never
a raw key value, anywhere in the source.
Git/GitHub hiccups along the way (not code bugs, but worth documenting)
"Author identity unknown" — first commit attempt on this VM failed
because git didn't have a configured identity yet. Fixed with
git config --global user.name / user.email.
Password authentication rejected — GitHub no longer accepts a plain
account password for git operations over HTTPS. Had to generate a
fine-grained Personal Access Token (Contents: Read and write, scoped to
this repo only) and use that as the password instead.
Screenshots uploaded to the wrong location — uploading directly
through GitHub's web UI without first being inside the screenshots/
folder caused the images to land in the repo root instead. Fixed by
editing each file directly and renaming its path to
screenshots/<filename>, which moves it into the folder.
