"""
Step 7 - Confidence Scoring

Simple, explainable formula (no black-box ML needed here - Member 5 owns
ML for behavioral detection; this is just IOC trust scoring):

confidence = source_score + recency_score + reputation_score
(clamped to 0.0 - 1.0)

- source_score: more independent sources reporting it -> more trust
- recency_score: recently seen -> more trust than something stale
- reputation_score: feed-provided reputation (e.g. AbuseIPDB's own score),
  averaged and scaled in, when available
"""

import datetime


def _source_score(num_sources):
    # 1 source -> 0.3, 2 -> 0.5, 3+ -> 0.7 (caps out, diminishing returns)
    if num_sources <= 1:
        return 0.3
    if num_sources == 2:
        return 0.5
    return 0.7


def _recency_score(last_seen_iso):
    try:
        last_seen = datetime.datetime.fromisoformat(str(last_seen_iso).replace("Z", ""))
        if last_seen.tzinfo is not None:
            # normalize to naive UTC so we can subtract safely
            last_seen = last_seen.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    except (ValueError, AttributeError, TypeError):
        return 0.1  # unknown recency -> low trust bump
    age_days = (datetime.datetime.utcnow() - last_seen).days
    if age_days <= 2:
        return 0.3
    if age_days <= 14:
        return 0.2
    if age_days <= 45:
        return 0.1
    return 0.0  # old IOC, no bump


def _reputation_score(reputation_hints):
    if not reputation_hints:
        return 0.0
    avg = sum(reputation_hints) / len(reputation_hints)  # typically 0-100 scale
    return min(avg / 100.0, 1.0) * 0.2  # weight capped at 0.2 of total score


def calculate_confidence(num_sources, last_seen_iso, reputation_hints=None):
    score = (
        _source_score(num_sources)
        + _recency_score(last_seen_iso)
        + _reputation_score(reputation_hints or [])
    )
    return round(min(score, 1.0), 2)


def confidence_label(score):
    if score >= 0.7:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"


if __name__ == "__main__":
    now = datetime.datetime.utcnow().isoformat()
    print(calculate_confidence(3, now, [90, 85]))   # expect high
    print(calculate_confidence(1, "2025-01-01T00:00:00"))  # expect low
