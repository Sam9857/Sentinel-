# BitSentinel SOC dashboard — guide

## Run it
```bash
pip install -r requirements.txt        # adds python-dotenv
copy .env.example .env                 # Windows  (Linux/macOS: cp .env.example .env)
python app.py                          # http://127.0.0.1:5000
```
Opens straight on the SOC dashboard. Original dashboard: `/legacy`. Workflow page: `/workflow`.
Set `SENTINEL_REQUIRE_LOGIN=true` to bring back the original login page (it also protects `/api/*` and `/stream/*`).

## Architecture
```
Browser UI (static/js/soc/views/*, components/*)
      ↓ calls only
Services   (static/js/soc/services/: socService · intelService · opsService · liveFeed)
      ↓ HTTP
Flask routes (routes/soc_routes.py · routes/intel_routes.py · + original routes)
      ↓
Python services (services/soc_service · ip_intelligence_service · malware_service · geo_service · providers)
      ↓ keys from .env (server only)
VirusTotal · AbuseIPDB · IPinfo · IPQualityScore        +  original engine (models/, utils/, data/*.json)
```

## API integration
| API | Purpose | Where it is called | Env var |
|---|---|---|---|
| VirusTotal v3 | IP verdicts, file/hash lookup | `services/providers.py` → `virustotal_ip()`, `virustotal_file()` | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB v2 | Abuse confidence, reports | `services/providers.py` → `abuseipdb_check()` | `ABUSEIPDB_API_KEY` |
| IPinfo | Geo, ASN, org (also feeds the map) | `services/providers.py` → `ipinfo_lookup()` | `IPINFO_API_KEY` |
| IPQualityScore | Proxy / VPN / Tor | `services/providers.py` → `ipqs_lookup()` | `IPQS_API_KEY` |

Merged by `services/ip_intelligence_service.py` → `GET /api/intel/ip/<ip>`. Files: `POST /api/intel/file` (hashed locally, only SHA-256 sent to VirusTotal). To add a provider: write one function in `providers.py`, add a key getter in `settings.py`, merge it in `ip_intelligence_service.lookup()`.

Keys: only in `.env` / server environment. Never in `static/` or templates. Free VirusTotal = 4 req/min, so results are cached for 1 hour (`services/cache.py`). The browser only talks to same-origin `/api/*`, so no CORS setup is needed.

## Data modes
`auto` (default) uses your `data/threats.json` once it has ≥25 records, otherwise the **demo dataset** — simulated traffic scored by the real engine (`services/demo_data.py`), never written to disk. Private/documentation IPs get a labelled *simulated* geo/intel profile and are never sent to third parties. Change in Settings → Dashboard data.

## Severity
90–100 critical · 61–89 high · 31–60 medium · 1–30 low · 0 informational (`services/severity.py`; the engine's own safe/suspicious/danger is unchanged).

## Workflow (what happens to an event)
1 event arrives → 2 parsed and grouped per IP → 3 IP/hash extracted → 4 intel APIs queried in parallel → 5 pattern rules + anomaly model → 6 weighted 0–100 score → 7 severity assigned → 8 dashboard updated (SSE) → 9 auto-block / alert → 10 analyst investigates, blocks, trusts or exports.

## Hinglish
Dashboard ka kaam hai saari security events ek jagah dikhana. Koi request ya log line aati hai to system har IP ke liye request count, failed login, error rate nikalta hai. Phir regex rules (SQL injection, XSS, brute force) aur ek ML model (IsolationForest) check karte hain ki traffic normal hai ya nahi. In sab se 0–100 ka risk score banta hai, aur score se severity (Critical se Info tak) milti hai. Agar score threshold se upar gaya to IP automatically block ho jaata hai. Map par har attacker ka country dikhta hai aur ek line us se aapke server (default Mumbai) tak jaati hai — line jitni laal, utna khatarnak. Kisi bhi IP par click karo to side panel khulta hai jahan VirusTotal, AbuseIPDB, IPinfo ka data aata hai. API keys sirf `.env` file mein jaati hain, browser ko kabhi nahi dikhti. Bina keys ke bhi sab chalta hai — demo data "simulated" label ke saath dikhta hai. "Live monitor" start karoge to dashboard apne aap aapke real data par switch ho jaata hai.

## 2–3 minute demo
1. (0:00) Open `/`. "SOC view: KPIs on top, mean risk gauge, live map and event feed." Point at the *Demo data* chip: simulated traffic, real detection engine.
2. (0:30) Map: arcs and particles are attack paths into Mumbai. Hover a source, click a red one → *Investigate IP*.
3. (1:00) Drawer: intelligence score, AbuseIPDB/VirusTotal/IPinfo structure; keys go in `.env` (show `.env.example`). Close it.
4. (1:20) Switch 24H → 7D: KPIs, chart and map refilter. Click a severity row → filtered threat table; search, sort, export CSV.
5. (1:50) Network activity → *Start live monitor* (Simulate). Dashboard switches to live data. Mention auto-block threshold in Settings.
6. (2:20) *How it works* → "Walk me through it": every stage names the file that implements it.
7. (2:45) Close: nothing from the original engine was removed; the old UI is still at `/legacy`.
