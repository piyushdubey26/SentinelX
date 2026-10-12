# ADR-003: Deterministic DSA-Based Detection Engine

## Status
Accepted

## Context
Detecting security threats (such as brute force logins, credential stuffing, and port scanning) requires evaluating event counts over continuous time windows (e.g., 5 failed logins within 60 seconds from the same IP). Querying the database with `SELECT COUNT(*) WHERE timestamp > NOW() - INTERVAL '60s'` on every incoming event produces $O(N)$ table scans and degrades database performance under high ingestion rates.

## Decision
We implement in-memory **Data Structures & Algorithms (DSA)** for deterministic stateful detection:
1. **Sliding Window via Deque/Queue**: Maintains timestamped occurrences within a sliding window. Eviction of expired events runs in amortized $O(1)$ time, yielding $O(1)$ lookup per incoming event.
2. **Hash Tables (HashMap/HashSet)**: Indexes events by correlation keys (e.g., `ip_address`, `user_id`, `target_asset`) with $O(1)$ average-case insertion and lookup.
3. **Priority Queue (Min/Max Heap)**: Orders pending alerts and incident evaluations by severity and triage urgency in $O(\log K)$ time.

## Consequences
- **Positive**: Microsecond detection latency, negligible database load during continuous event ingestion.
- **Negative**: In-memory state is process-bound unless periodically checkpointed or backed by distributed memory (planned for Redis integration in Milestone 1.5).
