"""
scheduler.py - keeps the pipeline running forever, re-collecting every
30 minutes. Leave this running in a terminal window (or turn it into a
background service later).

Run: py scheduler.py
Stop: Ctrl+C
"""

import time
from pipeline import run_pipeline

INTERVAL_SECONDS = 30 * 60  # 30 minutes - change if you want more/less frequent

if __name__ == "__main__":
    print(f"Scheduler started. Running pipeline every {INTERVAL_SECONDS // 60} minutes.")
    print("Press Ctrl+C to stop.\n")
    while True:
        try:
            run_pipeline()
        except Exception as e:
            print(f"[scheduler] pipeline run failed: {e}")
        print(f"\nSleeping {INTERVAL_SECONDS // 60} minutes until next run...\n")
        time.sleep(INTERVAL_SECONDS)
