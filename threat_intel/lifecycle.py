"""
Step 8 - IOC Lifecycle

Status progression:  New -> Active -> Stale -> Expired

- New:     first time we've ever seen it (no prior last_seen in DB)
- Active:  seen within STALE_AFTER_DAYS
- Stale:   not seen recently, but not old enough to drop
- Expired: older than EXPIRE_AFTER_DAYS -> effectively retired
"""

import datetime
from config import STALE_AFTER_DAYS, EXPIRE_AFTER_DAYS


def compute_status(first_seen_iso, last_seen_iso, is_new_record):
    if is_new_record:
        return "New"

    try:
        last_seen = datetime.datetime.fromisoformat(str(last_seen_iso).replace("Z", ""))
        if last_seen.tzinfo is not None:
            last_seen = last_seen.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    except (ValueError, AttributeError, TypeError):
        return "Active"  # can't parse -> assume fresh, don't silently drop it

    age_days = (datetime.datetime.utcnow() - last_seen).days

    if age_days > EXPIRE_AFTER_DAYS:
        return "Expired"
    if age_days > STALE_AFTER_DAYS:
        return "Stale"
    return "Active"


if __name__ == "__main__":
    now = datetime.datetime.utcnow().isoformat()
    print(compute_status(now, now, is_new_record=True))    # New
    print(compute_status(now, now, is_new_record=False))   # Active
