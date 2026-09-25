"""
inspect_db.py - quick look at what's actually in your IOC database.
Run this from inside the threat_intel folder: py inspect_db.py
"""

from database import get_connection, count_iocs

conn = get_connection()
total = count_iocs(conn)
print(f"Total IOCs in database: {total}\n")

print("Sample of 10 stored IOCs:")
print("-" * 80)
cur = conn.cursor()
cur.execute("SELECT ioc, type, sources, confidence, mitre, status FROM iocs LIMIT 10")
for row in cur.fetchall():
    ioc, ioc_type, sources, confidence, mitre, status = row
    print(f"IOC:        {ioc}")
    print(f"Type:       {ioc_type}")
    print(f"Sources:    {sources}")
    print(f"Confidence: {confidence}")
    print(f"MITRE:      {mitre}")
    print(f"Status:     {status}")
    print("-" * 80)

print("\nBreakdown by type:")
cur.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY COUNT(*) DESC")
for ioc_type, count in cur.fetchall():
    print(f"  {ioc_type}: {count}")

conn.close()
