# Member 2 — Threat Intelligence Pipeline

## Setup
```bash
pip install requests fastapi uvicorn
```

## Get free API keys
- AbuseIPDB: https://www.abuseipdb.com/register
- OTX: https://otx.alienvault.com/ (account → API key in profile)
- URLhaus / MalwareBazaar: no key needed

Set them as environment variables (don't hardcode / commit them):
```bash
export ABUSEIPDB_API_KEY="your_key"
export OTX_API_KEY="your_key"
```
Or paste directly into `config.py` for local testing only.

## Run the pipeline
```bash
python3 pipeline.py
```
This collects from all 4 feeds → validates → normalizes → dedupes →
enriches → scores confidence → maps MITRE ATT&CK → stores in
`data/ioc_store.db` (SQLite).

## Run the query API (for Member 5 / Member 8)
```bash
uvicorn api:app --reload --port 8001
```
Then: `GET http://localhost:8001/ioc/185.220.101.5?type=ip`

## File map (maps to your 11 pipeline steps)
| Step | File |
|---|---|
| 1-2. Sources & Collectors | `collectors.py` |
| 3. Validate | `validator.py` |
| 4. Normalize | `normalizer.py` |
| 5. Deduplicate | `dedup.py` (+ 2nd pass in `database.py`) |
| 6. Enrich | `enrichment.py` |
| 7. Confidence score | `confidence.py` |
| 8. Lifecycle | `lifecycle.py` |
| 9. MITRE mapping | `mitre_mapper.py` |
| 10. Storage | `database.py` |
| 11. Query API | `api.py` |
| Orchestrator | `pipeline.py` |

## Next steps for you
1. Drop in your real API keys and run `pipeline.py` once to confirm live data flows.
2. Schedule it (cron, or `APScheduler` inside a small `scheduler.py`) to run every 15–30 min.
3. Talk to Member 8 before deploying `api.py` standalone — they may want
   `lookup_ioc()` imported straight into their FastAPI app instead of a
   second server running on a different port.
4. Swap SQLite for Postgres in `database.py` once Member 8 shares the shared schema — only `get_connection()` needs to change.
5. Extend `mitre_mapper.py`'s tag table as Member 4's attack scenarios solidify, so your MITRE coverage actually lines up with what's demoed.
