"""
config.py
Central place for API keys and tunable constants.
Set keys via environment variables (recommended) or paste directly below for testing.

Get free API keys here:
  AbuseIPDB : https://www.abuseipdb.com/register
  OTX       : https://otx.alienvault.com/  (create account -> API key in your profile)
  URLhaus   : no key needed
  MalwareBazaar : no key needed
"""

import os

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
# abuse.ch now requires a free Auth-Key for MalwareBazaar (& URLhaus auth endpoints).
# Get one at: https://auth.abuse.ch/
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")

# How many days back to consider an IOC "Active" vs "Stale" vs "Expired"
STALE_AFTER_DAYS = 14
EXPIRE_AFTER_DAYS = 45

# SQLite DB path (swap this for the Postgres connection Member 8 gives you later)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "ioc_store.db")

# Basic request timeout / retry
REQUEST_TIMEOUT = 15
