"""
Minimal Integration Example for zero_day_anomaly_detector.pkl.
Shows how Member 3 (Digital Twin), Member 6 (SIEM/Monitoring), or any downstream service
can load the trained pickle model and detect zero-day threats in real time.
"""

import pickle

MODEL_FILE = "zero_day_anomaly_detector.pkl"

def main():
    # 1. Load the pre-trained model pickle
    print(f"Loading {MODEL_FILE}...")
    with open(MODEL_FILE, "rb") as f:
        detector = pickle.load(f)

    print(f"Loaded detector: version={detector.version}, trained_at={detector.trained_at}")

    # 2. Example 1: Evaluating a Routine / Normal Event
    normal_event = {
        "event_id": "EVT-NORM-001",
        "timestamp": "2026-09-11T10:15:30Z",
        "event_type": "PROCESS",
        "hostname": "WS-FIN-02",
        "user": "bob.fin",
        "image": "excel.exe",
        "parent_image": "explorer.exe",
        "command_line": "excel.exe C:\\Users\\bob.fin\\Documents\\Ledger_2026.xlsx",
        "details": "User opened Excel sheet"
    }

    result_normal = detector.evaluate_event(normal_event, host_criticality="HIGH")
    print("\n--- Normal Event Evaluation ---")
    print(f"Anomaly Score : {result_normal['anomaly_score']}")
    print(f"Decision      : {result_normal['decision']} (Severity: {result_normal['severity']})")

    # 3. Example 2: Evaluating an Unknown / Zero-Day Attack Event (No known signature)
    zero_day_event = {
        "event_id": "EVT-ZERODAY-001",
        "timestamp": "2026-09-11T02:45:10Z",  # Off-hours execution (2:45 AM)
        "event_type": "PROCESS",
        "hostname": "WS-EXEC-01",
        "user": "alice.exec",
        "image": "calc.exe",
        "parent_image": "spoolsv.exe",         # Unprecedented parent-child lineage
        "command_line": "calc.exe -d 7b8a9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f -mem_sync 0x00400000",
        "details": "calc.exe spawned with abnormal memory parameter under spoolsv.exe"
    }

    result_zeroday = detector.evaluate_event(zero_day_event, host_criticality="HIGH")
    print("\n--- Zero-Day Threat Evaluation ---")
    print(f"Anomaly Score : {result_zeroday['anomaly_score']}")
    print(f"Decision      : {result_zeroday['decision']} (Severity: {result_zeroday['severity']})")
    print(f"Risk Score    : {result_zeroday['risk_score']} (Adjusted for HIGH criticality host)")
    print("Root Cause Explanations:")
    for reason in result_zeroday["top_reasons"]:
        print(f"  * {reason}")

if __name__ == "__main__":
    main()
