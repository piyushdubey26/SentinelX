# ADR-006: Multi-Attribute Event Correlation, Anti-IP-Bleeding Safety & Candidate Incident Lifecycle

## Status
Accepted

## Context
In an enterprise Security Operations Center (SOC), raw telemetry arrives as thousands of isolated, noisy events. Evaluating events in isolation produces extreme *alert fatigue*, while naive correlation—specifically grouping events solely by IP address—causes severe architectural harm ("IP Bleeding" / false correlation explosion):
1. **Corporate NAT Gateways**: Thousands of legitimate corporate employees route through a single public egress IP (e.g. `198.51.100.99`). Merging all alerts from that IP erroneously collates disjoint user sessions into a giant false-positive incident.
2. **Corporate VPN Egress Pools**: Remote staff globally share revolving IP ranges.
3. **Reverse Proxies & Cloud CDNs**: Infrastructure (Cloudflare, AWS ALB) fronts distinct applications with shared IP endpoints.
4. **DHCP Leasing**: Dynamic workstation IP reassignment shifts addresses across completely different physical machines.

## Decisions

### 1. Anti-IP-Bleeding Rule & Explicit Evidence Requirements
**Rule: An IP address is NEVER sufficient by itself to merge security events.**

Events are only correlated into the same candidate cluster if they share at least one **primary anchor**:
- **Primary Anchor 1 (Identity)**: Matching `targetUser` / `actorUser` within the sliding window.
- **Primary Anchor 2 (Asset)**: Matching `assetId` / destination host within the sliding window.
- **Primary Anchor 3 (Attack Chain Progression)**: Valid MITRE ATT&CK progression transition (e.g., `AUTH_FAILURE` $\to$ `AUTH_SUCCESS` or `BRUTE_FORCE` $\to$ `PRIVILEGE_ESCALATION`).

When a shared source IP is present without any primary anchor, the correlation engine **explicitly rejects** the link, assigns zero weight, and records a rejected factor (`SHARED_SOURCE_IP_REJECTED`) containing the safeguard explanation.

### 2. Multi-Attribute Scoring Rubric & Versioned Configuration

Confidence scores are defined as a ranking signal $S \in [0.0, 1.0]$:

$$S(E, C) = \min\left(1.0, \sum_{k} w_k \cdot \text{Match}_k(E, C)\right)$$

| Dimension | Weight ($w_k$) | Evaluation Criteria |
| :--- | :--- | :--- |
| **Shared Identity** | `0.35` | Case-insensitive match on `targetUser` / `actorUser` |
| **Shared Asset** | `0.30` | Exact match on `assetId` |
| **Attack Progression** | `0.25` | Valid MITRE ATT&CK kill-chain transition |
| **Reinforced Network Pair** | `0.15` | Matching `sourceIp` **paired with** matched identity, asset, or progression |
| **Shared IP Alone** | `0.00` | Same `sourceIp`, disjoint identities/assets $\to$ **REJECTED** |

#### Missing Data Behavior:
- If `targetUser` is missing/null, `Shared Identity` evaluates to 0.0 contribution (no credit).
- If `assetId` is missing/null, `Shared Asset` evaluates to 0.0 contribution.
- Missing attributes never throw exceptions and never artificially inflate the score.

#### Confidence Interpretation & Thresholds:
- **Score is a ranking signal, NOT proof of attack**: It expresses heuristic aggregation confidence.
- **Correlation Threshold (`0.50`)**: Minimum score required to link an incoming event into an existing candidate incident cluster.
- **Auto-Promotion Threshold (`0.85`)**: High-confidence threshold (or critical kill-chain progression) that triggers automatic promotion to a confirmed incident.

### 3. Data Structures & Algorithmic Complexity

Rather than executing $O(N)$ full-table database scans on every incoming event, the `CorrelationEngine` maintains an in-memory compound sliding-window index.

#### Operations Breakdown:
1. **Candidate Cluster Lookup (`findCandidateClusterIds`)**:
   - Compound inverted hash maps: `userIndex`, `assetIndex`, `ipIndex`.
   - **Average Complexity**: $O(1)$ amortized to retrieve candidate cluster IDs.
   - **Worst-case Complexity**: $O(k)$ where $k$ is the number of active overlapping clusters for the entity in the sliding window ($k \le 5$ in normal operation; bounded by active window cardinality).
2. **Evaluation & Scoring (`evaluateMatch`)**:
   - Compares event attributes against candidate cluster state.
   - **Complexity**: $O(1)$ per candidate cluster.
3. **Cluster Update / Insertion**:
   - Updates time bounds $[t_{\min}, t_{\max}]$, appends event ID, updates inverted index.
   - **Complexity**: $O(1)$ amortized.
4. **Time-Window Eviction (`evictExpired`)**:
   - Periodically purges clusters whose `lastSeen < now - W` (default $W = 15\text{ minutes}$).
   - **Complexity**: $O(E \cdot \text{deg})$ where $E$ is the number of expired clusters and $\text{deg}$ is the number of indexed keys per cluster. Amortized per event: $O(1)$.
   - **Worst-case**: If $C$ clusters expire simultaneously in a single tick, eviction takes $O(C)$.

#### Empirical Benchmark Evidence (20,000 Events):
- **Incremental Indexed Engine**: Total time **73.35 ms**, Throughput **272,662 events/sec**, p50 **0.0026 ms** (2.6 µs).
- **Naive Full-Rescan Baseline**: Total time **886.53 ms**, Throughput **22,559 events/sec**, p50 **0.0440 ms**.
- **Advantage**: Incremental indexed processing is **12.09x faster** and avoids polynomial quadratic explosion as cluster count grows.

### 4. Candidate Incident Lifecycle & Provenance

```
  [Security Telemetry / Detections]
                 │
                 ▼
       [Correlation Engine]
                 │
                 ├── Score < 0.50 ──► (Disjoint / New Cluster)
                 │
                 └── Score >= 0.50 ──► [Candidate Incident] (status: CANDIDATE)
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       ▼                                             ▼
             [Analyst / Auto Promote]                      [Analyst Dismiss]
                       │                                             │
                       ▼                                             ▼
           [Confirmed Incident (INC-xxxx)]                 (status: DISMISSED)
           (status: PROMOTED)                              (with reason & user audit)
```

- **Candidate vs Confirmed**: Candidate incidents (`candidate_incidents` table) represent hypothesis clusters. Confirmed incidents (`incidents` table) represent triaged operational incidents.
- **Provenance Preservation**: `event_ids UUID[]` and `detection_ids UUID[]` track every source record.
- **Idempotency**: Repeated promotion calls return the existing promoted candidate and incident without creating duplicate `INC-xxxx` records.
- **State Transition Guard**: Dismissed candidates cannot be promoted; promoted candidates cannot be dismissed. All transitions log to `audit_logs`.

## Consequences
- **Positive**: Strict elimination of false-positive NAT/VPN IP merges, sub-millisecond incremental correlation, clear analyst explainability with factor contributions, and full state transition auditability.
- **Negative**: High-volume attacks targeting thousands of distinct users require active window memory pruning to keep memory footprint bounded.
