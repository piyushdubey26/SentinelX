# ADR-007: Graph-Based Security Investigation, Attack Path Discovery & Blast-Radius Analysis

## Status
Accepted

## Context
In a security operations center (SOC), analysts investigating complex incidents need to trace how suspicious activity propagates across users, hosts, IP addresses, and detection rules. Relational tables and flat alert lists obscure multi-hop relationships such as lateral movement, credential reuse across assets, and multi-stage kill chains.

However, introducing a full external graph database (e.g., Neo4j) at this stage introduces substantial operational complexity:
1. Operational overhead of maintaining an additional distributed database cluster and synchronization pipeline.
2. Eventual consistency mismatches with PostgreSQL's ACID transaction boundaries.
3. Network round-trip latency for sub-graph queries on small-to-medium incident clusters ($N < 5,000$ entities).

Furthermore, graph representations in security must avoid two common architectural pitfalls:
1. **IP Bleeding in Graph Topology**: In multi-tenant, VPN, or NAT environments, naive graph edges connecting all entities sharing an IP address cause massive false-positive cluster explosion.
2. **False Assumptions of Compromise**: Graph reachability from a compromised node must never be treated as definitive proof of compromise for all reachable nodes. Evidence provenance must clearly distinguish observed facts from inferred relationships.

---

## Decisions

### 1. In-Memory Graph Architecture
For SentinelX Milestone 2.3, graph structures are constructed dynamically in-memory from PostgreSQL relational entities (`Incident`, `CandidateIncident`, `SecurityEvent`, `Asset`, `Detection`) via `GraphBuilderService` and processed using an optimized adjacency-list engine (`InvestigationGraph`).

- **Dual Adjacency Lists**: Maintains both `outgoingEdges` and `incomingEdges` (`Map<string, GraphEdge[]>`) for fast forward and reverse traversals.
- **Deduplication & Invariant Validation**: Edges are indexed by deterministic URNs (`${sourceId}->${edgeType}->${targetId}`). Re-insertions update confidence if higher, avoiding redundant edge traversals.
- **Zero External Infrastructure**: Eliminates third-party graph database dependencies while delivering microsecond-range traversal latency.

### 2. Graph Data Model & Directional Causality

#### Node Entities (`GraphNodeType`)
- `INCIDENT`: Root incident boundary container.
- `SECURITY_EVENT`: Telemetry event instance with timestamp, category, and severity.
- `DETECTION`: Correlated detection rule or alert signature.
- `USER`: Identity actor or targeted account.
- `IP_ADDRESS`: Source or destination network IP address.
- `ASSET`: Internal enterprise infrastructure host or service.

#### Edge Semantics (`GraphEdgeType`)
Directionality reflects natural causality and attack progression:
- `CONNECTED_FROM`: `IP_ADDRESS` $\to$ `SECURITY_EVENT` (traffic originating from network address).
- `TARGETED_ASSET`: `SECURITY_EVENT` $\to$ `ASSET` (event targeting destination host).
- `AUTHENTICATED_AS`: `SECURITY_EVENT` $\to$ `USER` (event authenticating with credentials).
- `TARGETED_USER`: `SECURITY_EVENT` $\to$ `USER` (event targeting user identity).
- `RESOLVES_TO`: `ASSET` $\to$ `IP_ADDRESS` (host bound to IP interface).
- `TRIGGERED`: `SECURITY_EVENT` $\to$ `DETECTION` (event matching detection rule).
- `PART_OF_INCIDENT`: `SECURITY_EVENT` / `DETECTION` $\to$ `INCIDENT` (association to incident).
- `PRECEDED_BY`: `SECURITY_EVENT` $\to$ `SECURITY_EVENT` (temporal kill-chain sequence).
- `ASSOCIATED_WITH`: Entity $\to$ Entity (corroborated by correlation factor).

#### Strict Anti-IP-Bleeding Safeguard
Direct `USER` $\leftrightarrow$ `USER` or `ASSET` $\leftrightarrow$ `ASSET` edges without an explicit correlation factor (`ASSOCIATED_WITH` corroborated by identity, asset, or progression) are rejected during edge insertion (`InvestigationGraph.addEdge()`). An IP address alone is never permitted to bridge disjoint identity clusters.

#### Evidence Provenance
Every edge encapsulates provenance metadata:
```typescript
interface GraphEdgeProvenance {
  sourceRecordId?: string;
  recordType: string;       // e.g., 'SECURITY_EVENT', 'DETECTION', 'ASSET_INVENTORY'
  timestamp: string;
  confidence: number;       // 1.0 for directly observed telemetry; 0.5 - 0.9 for inferred correlations
  evidenceDetails?: Record<string, any>;
}
```

---

### 3. Core Graph Algorithms & Complexity Guarantees

#### A. Breadth-First Search (BFS) Neighborhood Exploration
- **Implementation**: Queue-based traversal with `visited` set and distance mapping.
- **Safety Ceilings**: Enforces `maxHops <= 5` and `maxNodes <= 500`. Supports optional temporal window filtering $[t_{\min}, t_{\max}]$.
- **Time Complexity**: $O(V + E)$ bounded by traversal ceilings.
- **Space Complexity**: $O(V)$ for queue and visited distance maps.

#### B. Depth-First Search (DFS) Multi-Hop Attack Path Finding
- **Implementation**: Explicit stack-based iterative DFS avoiding V8 call-stack limits. Employs a tracking set to prevent cycle loops within active traversal paths.
- **Pruning**: Prunes paths exceeding `maxDepth` (capped at 6) or dropping below `minConfidence`. Collects up to `maxPaths` (capped at 20).
- **Confidence Scoring**: Each discovered path computes an aggregate confidence product:
  $$\text{Confidence}(P) = \prod_{e \in P} \text{confidence}(e)$$
- **Time Complexity**: $O(b^d)$ worst-case where $b$ is average out-degree and $d \le 6$; tightly bounded in practice by depth/path limits and cycle prevention.
- **Space Complexity**: $O(d \cdot \text{maxPaths})$ for stack and path accumulation.

#### C. Blast Radius Analysis & Tiered Attribution
Calculates the operational impact radius around a focal compromised entity or root incident:
- **Tier 1 (Confirmed Directly Observed)**: Entities directly observed in telemetry events or detections ($1$ hop or direct target).
- **Tier 2 (Potentially Exposed)**: Transitive downstream reachability via lateral progression or shared infrastructure ($>1$ hops).
- **Critical Asset Identification**: Explicitly flags reachable assets where `isCritical: true` or `criticality === 'CRITICAL'`.
- **Mandatory Disclaimer**: Every blast radius response includes the standard disclaimer:
  > *"Graph reachability indicates potential attack or pivot paths based on observed telemetry and correlation topology. It does NOT constitute definitive proof of asset compromise."*

#### D. Directed Cycle Detection
- **Implementation**: 3-Color DFS algorithm (`WHITE` = unvisited, `GRAY` = currently on DFS recursion stack, `BLACK` = fully explored).
- **Cycle Validation**: Any edge pointing to a `GRAY` node indicates a back-edge and directed cycle. Trivial reciprocal edges ($A \to B \to A$) between the same two entities are filtered to focus on non-trivial circular pivot loops.
- **Time Complexity**: $O(V + E)$ on the directed graph.
- **Space Complexity**: $O(V)$ for state tracking and parent maps.

---

### 4. API Endpoints, RBAC & Protection Controls

The graph investigation capabilities are exposed via `InvestigationsController`:
- `GET /api/v1/investigations/incident/:id/graph` — Incident subgraph visualization payload.
- `GET /api/v1/investigations/incident/:id/paths` — Attack path discovery between source and target nodes.
- `GET /api/v1/investigations/incident/:id/blast-radius` — Tiered blast-radius analysis.
- `GET /api/v1/investigations/incident/:id/cycles` — Directed feedback loops and cycle detection.

#### Security Controls:
1. **Authentication & RBAC**: Guarded with `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles(UserRole.ADMIN, UserRole.ANALYST)`. Unauthenticated or unauthorized callers receive `401 Unauthorized` or `403 Forbidden`.
2. **IDOR & Resource Validation**: Verifies target incident exists before graph generation; returns `404 Not Found` for invalid IDs.
3. **Query Parameter Ceilings**: Enforced via `InvestigationQueryDto` with class-validator:
   - `maxHops`: Min 1, Max 5 (default 3)
   - `maxDepth`: Min 1, Max 6 (default 4)
   - `maxPaths`: Min 1, Max 20 (default 10)
   - `minConfidence`: Min 0.0, Max 1.0 (default 0.1)
4. **Audit Logging**: Every graph access is audited via `AuditService.log()` recording user ID, action, incident ID, and node count.

---

### 5. Algorithmic Benchmark Methodology & Verified Results

A reproducible benchmark suite (`backend/scripts/benchmark-graph.js`) was executed using a deterministic pseudo-random number generator (LCG seed = 4242) across small, medium, and large graph topologies on macOS ARM64 (Node.js v26.5.0):

| Graph Scale | Nodes / Edges | Construction Median | BFS (Hops=3) Median | DFS Pathfinding Median | Blast Radius Median | Cycle Detection Median |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 100 / 160 | $282.8\,\mu\text{s}$ | $3.3\,\mu\text{s}$ (297k ops/s) | $61.9\,\mu\text{s}$ (8.6k ops/s) | $17.0\,\mu\text{s}$ (33.8k ops/s) | $33.0\,\mu\text{s}$ (26.4k ops/s) |
| **Medium** | 500 / 664 | $1.087\,\text{ms}$ | $0.2\,\mu\text{s}$ (5.49M ops/s) | $52.3\,\mu\text{s}$ (18.6k ops/s) | $6.5\,\mu\text{s}$ (140k ops/s) | $129.1\,\mu\text{s}$ (7.5k ops/s) |
| **Large** | 1,950 / 2,498 | $4.361\,\text{ms}$ | $0.2\,\mu\text{s}$ (6.32M ops/s) | $3.4\,\mu\text{s}$ (265k ops/s) | $5.6\,\mu\text{s}$ (177k ops/s) | $464.2\,\mu\text{s}$ (1.9k ops/s) |

#### Important Benchmark Qualifications:
1. **Algorithmic Scope**: Evaluates pure in-memory performance of the adjacency-list graph data structures and graph traversal algorithms.
2. **Exclusions**: Does **not** include PostgreSQL relational query latency, ORM serialization overhead, or HTTP REST JSON payload serialization.
3. **Safety Limits**: Traversal ceilings prevent pathological exponential blowup on dense graphs.

---

## Consequences

### Positive
- Zero external database operational footprint; runs natively inside the NestJS modular monolith.
- High-performance microsecond-range algorithmic execution for interactive analyst queries.
- Strict anti-IP-bleeding invariants maintain correlation integrity.
- Clear separation between directly observed telemetry facts and inferred correlations.
- Complete test coverage across unit tests (12 tests) and end-to-end integration tests (9 tests).

### Negative / Trade-offs
- Incident graph scale is constrained by single-node process memory (bounded to $\approx 5,000$ nodes per incident cluster, which is more than sufficient for incident-scoped investigation).
- Cross-incident global knowledge graph across millions of historical events will require future distributed storage evaluation if ever needed.
