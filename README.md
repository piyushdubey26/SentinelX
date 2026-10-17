# SentinelX — AI-Assisted Security Operations Center (SOC)

[![Backend Tests](https://img.shields.io/badge/backend%20tests-96%2F96%20passing-brightgreen)](#verified-test--build-evidence)
[![Frontend Build](https://img.shields.io/badge/frontend%20build-passing-brightgreen)](#frontend-production-build)
[![Current Gate](https://img.shields.io/badge/gate-Milestone%202.4%20IMPLEMENTED%20%26%20VERIFIED-brightgreen)](#project-status--milestone-gates)
[![Milestone 2.5](https://img.shields.io/badge/milestone%202.5-ON%20HOLD-orange)](#project-status--milestone-gates)

SentinelX is a production-grade, testable Security Operations Center (SOC) platform designed to ingest high-velocity security telemetry, execute deterministic detection rules using algorithmic data structures (DSA), correlate related events into candidate incident clusters without false-positive IP merges, explore incident relationships using graph traversal algorithms (BFS/DFS, blast radius, cycle detection), prioritize triage queues via explainable risk scoring and binary heap priority queues, manage full incident lifecycles, and deliver evidence-grounded threat intelligence to security analysts.

---

## Project Status & Milestone Gates

| Milestone | Scope | Status | Acceptance Gate Verification |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Foundation, PostgreSQL Schema, Auth, RBAC, Sliding-Window Detector, Analyst UI | **COMPLETED** | Verified at commit `70b1c19` (All criteria met). |
| **Milestone 2.1** | Event Streaming, Idempotency, Dead-Letter Queue (DLQ), Consumer Retry | **COMPLETED** | Verified at commit `bf62c0c` ([ADR-005](docs/decisions/005-kafka-streaming-and-delivery-guarantees.md)). |
| **Milestone 2.2** | Multi-Attribute Correlation Engine, Anti-IP-Bleeding, Candidate Incident Lifecycle | **APPROVED WITH LIMITATIONS** | Verified at commit `55d150b` ([ADR-006](docs/decisions/006-event-correlation-and-anti-ip-bleeding.md)). |
| **Milestone 2.3** | Graph-Based Investigation (In-Memory Adjacency Engine, BFS/DFS, Blast Radius, Cycle Detection, Analyst UI) | **COMPLETED** | Verified at commit `50cfe86` ([ADR-007](docs/decisions/007-graph-investigation-and-blast-radius.md)). |
| **Milestone 2.4** | Explainable Incident Risk Scoring, Sublinear Dampening & Binary Heap Priority Queue | **IMPLEMENTED & VERIFIED** | Verified with 20 risk unit & integration tests passing ([ADR-008](docs/decisions/008-explainable-incident-risk-scoring.md)). |
| **Milestone 2.5** | Machine Learning Anomaly Detection (Isolation Forest / Autoencoders) | **ON HOLD** | Pending Milestone 2.4 approval. |
| **Milestone 2.6** | Evidence-Grounded AI Incident Copilot (RAG over MITRE ATT&CK & Runbooks) | **PLANNED** | Pending Milestone 2.5 completion. |
| **Milestone 2.7** | Real-Time Dashboard WebSocket Streaming | **PLANNED** | Pending Milestone 2.6 completion. |
| **Phase 3** | Enterprise Distributed Deployment, Kubernetes, Full Telemetry | **PLANNED** | Future roadmap. |

> [!NOTE]
> **Milestone 2.4 is IMPLEMENTED & VERIFIED.** Explainable risk scoring (Impact $\times$ Confidence $\times$ Recency), logarithmic event flood dampening, exponential half-life decay, binary heap `RiskPriorityQueue` ($O(\log N)$ / $O(N \log K)$ Top-K), REST APIs with RBAC, and the React analyst risk breakdown interface have been built and tested. Milestone 2.5 remains ON HOLD.

---

## Real-World SOC Use Case

Enterprise SOC environments suffer from severe **alert fatigue**, **false correlation explosion**, **opaque relationship sprawl**, and **unprioritized alert queues**:
1. **Corporate NAT / VPN Egress Pools**: Thousands of legitimate corporate employees route through shared public IP addresses (e.g. `198.51.100.99`). Naive correlation engines that group alerts solely by source IP erroneously merge disjoint user sessions into massive false-positive incidents ("IP Bleeding").
2. **Volumetric Telemetry vs Processing Latency**: Raw authentication and network telemetry arrives at thousands of events per second. Running unindexed $O(N^2)$ cross-event comparisons causes processing backpressure.
3. **Multi-Hop Pivot Discovery**: Disconnected table views obscure how an attacker pivoted from an initial phishing credential compromise through an intermediate jump host to an internal database server.
4. **Alert Queue Prioritization Bottlenecks**: Sorting incidents merely by creation timestamp forces analysts to wade through hundreds of low-severity alerts while active intrusions against mission-critical databases remain buried.
5. **Explainability & Diminishing Returns**: Linear alert counters allow automated script-kiddie attacks (e.g. 50,000 brute-force attempts) to inflate risk scores to infinity. SentinelX enforces sublinear logarithmic dampening and provides transparent mathematical factor breakdowns for every score.

---

## System Architecture

```
                      +-----------------------------+
                      |     React / Vite Frontend   |
                      |   (Enterprise SOC Console)  |
                      |  - Health Polling (10s)     |
                      |  - Prioritized Incident Q   |
                      |  - Risk Factor Breakdown    |
                      |  - Graph Investigation View |
                      +--------------+--------------+
                                     |
                                REST API (JWT)
                                     |
                      +--------------v--------------+
                      |    NestJS Modular Monolith  |
                      |  - Auth & RBAC (RolesGuard) |
                      |  - Event Ingestion Pipeline |
                      |  - In-Memory DSA Detector   |
                      |  - Inverted-Index Correlator|
                      |  - Graph Engine (BFS / DFS) |
                      |  - Risk Scoring & Max-Heap  |
                      |  - Candidate Lifecycle Mgr  |
                      |  - Audit & Security Logging |
                      |  - Streaming (In-Memory/MQ) |
                      +--------------+--------------+
                                     |
                         +-----------+-----------+
                         |                       |
                +--------v-------+      +--------v-------+
                |   PostgreSQL   |      |   AI Service   |
                | (TypeORM / Pg) |      | (FastAPI / ML) |
                | - Migrations   |      |  [Scaffolding  |
                | - Check Const. |      |   Only -       |
                | - Row Locking  |      |   Phase 2]     |
                +----------------+      +----------------+
```

---

## Technology Matrix: Implemented vs Planned

To avoid claiming unbuilt capabilities, the table below reflects the exact verified state of the repository:

| Capability / Component | Status | Implementation Details | Verified By |
| :--- | :---: | :--- | :--- |
| **Modular Monolith Backend** | **Implemented** | NestJS with domain modules (`auth`, `users`, `events`, `detections`, `incidents`, `investigations`, `risk`, `audit`, `streaming`, `correlation`, `health`). | `npm test` (96 tests passing) |
| **PostgreSQL Schema & Migrations** | **Implemented** | Reversible migrations `001`, `002`, `003`, `004` with foreign keys, check constraints, and compound indexes. | `scripts/test-migration-rollback.js` |
| **Authentication & RBAC** | **Implemented** | JWT access tokens, bcrypt password hashing, server-side `@Roles()` decorator, and `RolesGuard`. | `test/auth-security.spec.ts` |
| **Deterministic DSA Detector** | **Implemented** | In-memory sliding-window deque for brute-force pattern matching ($O(1)$ amortized insertion and eviction). | `sliding-window-detector.spec.ts` |
| **Event Streaming & Retries** | **Implemented** | Dual-mode streaming module: built-in in-memory broker with 3 partitions, idempotency key deduplication, and DLQ persistence. External Kafka configurable via env. | `test/streaming-pipeline.spec.ts` |
| **Multi-Attribute Correlation Engine** | **Implemented** | Inverted hash-indexed candidate clustering, anti-IP-bleeding safeguard ($w_{\text{IP}} = 0$ unanchored), calibrated weights summing to $1.000$, and explainability factors. | `test/correlation-engine.spec.ts` |
| **Candidate Incident Lifecycle** | **Implemented** | Separate `candidate_incidents` table, status transitions (`CANDIDATE`, `PROMOTED`, `DISMISSED`), idempotent promotion, PostgreSQL row locking (`pessimistic_write`). | `test/correlation-engine.spec.ts` |
| **Graph-Based Security Investigation** | **Implemented** | In-memory adjacency list (`InvestigationGraph`), BFS ($O(V+E)$), iterative DFS attack-path finding, tiered blast radius, 3-color directed cycle detection, REST endpoints with RBAC & audit logging. | `test/investigation-graph.spec.ts`, `test/investigations.spec.ts` (21 tests) |
| **Explainable Incident Risk Scoring** | **Implemented** | Mathematical scoring separating Impact from Confidence, logarithmic event flood dampening, exponential recency decay, binary heap `RiskPriorityQueue`, $O(N \log K)$ Top-K selection, REST APIs with RBAC. | `test/risk-scoring.spec.ts`, `test/risk-integration.spec.ts` (20 tests) |
| **Enterprise SOC Frontend** | **Implemented** | React 18, TypeScript, Vite, Tailwind CSS. Displays health badge, metrics cards, risk-prioritized incident queue, RiskBreakdown modal, and Graph Investigation modal. | `tsc && vite build` (0 errors) |
| **ML Anomaly Detection** | **Planned** | Python/FastAPI anomaly scoring using Isolation Forest / Autoencoders. Directory exists as scaffolding only. | Milestone 2.5 |
| **AI Incident Copilot** | **Planned** | RAG-grounded natural-language query assistant for incident summaries and remediation runbooks. | Milestone 2.6 |
| **Real-Time WebSockets** | **Planned** | Live dashboard push updates via WebSocket gateway. Current dashboard uses periodic HTTP polling (8s–10s). | Milestone 2.7 |

---

## Repository Structure

```
sentinelx/
├── backend/
│   ├── scripts/
│   │   ├── benchmark-correlation.js      # Deterministic LCG correlation benchmark
│   │   ├── benchmark-graph.js            # Reproducible graph traversal & cycle benchmark
│   │   ├── benchmark-risk.js             # Risk evaluation throughput & Top-K heap benchmark
│   │   ├── test-migration-rollback.js    # Disposable DB migration forward/down test
│   │   └── setup-db.js                  # Database initialization script
│   ├── src/
│   │   ├── audit/                       # Audit logging module
│   │   ├── auth/                        # JWT authentication, guards, and decorators
│   │   ├── common/                      # Health controller, filters, and interceptors
│   │   ├── config/                      # Database and application configuration
│   │   ├── correlation/                 # Multi-attribute correlation engine & candidate lifecycle
│   │   ├── detections/                  # DSA sliding-window brute-force detector
│   │   ├── events/                      # Event ingestion and normalization
│   │   ├── incidents/                   # Confirmed incident lifecycle management
│   │   ├── investigations/              # Graph-based investigation engine & APIs
│   │   ├── risk/                        # Explainable incident risk scoring & priority queue
│   │   │   ├── dsa/                     # Binary Heap PriorityQueue & Top-K algorithm
│   │   │   ├── risk-scoring.service.ts  # Mathematical scoring & persistence
│   │   │   ├── risk.controller.ts       # REST API endpoints with RBAC
│   │   │   ├── risk.module.ts           # NestJS module configuration
│   │   │   └── risk.types.ts            # Scoring rubric, interfaces, and weights
│   │   ├── streaming/                   # Dual-mode streaming broker, idempotency & DLQ
│   │   ├── users/                       # User and role entities
│   │   ├── app.module.ts                # Root application module
│   │   └── main.ts                      # Bootstrap entry point (Helmet, CORS, ValidationPipe)
│   └── test/                            # Integration and unit test suites (Jest)
├── frontend/
│   ├── src/
│   │   ├── app/                         # Main App component & layout
│   │   ├── components/                  # Header, MetricCard, and UI components
│   │   ├── features/                    # Auth form, IncidentQueue, RiskBreakdownView, InvestigationGraphView
│   │   ├── services/                    # Axios API client (includes risk and graph endpoints)
│   │   └── types/                       # TypeScript interfaces (including risk and graph entities)
│   ├── package.json
│   └── vite.config.ts
├── database/
│   ├── migrations/                      # Reversible PostgreSQL migrations (001, 002, 003, 004)
│   └── seeds/                           # Default roles and test users
├── docs/
│   └── decisions/                       # Architecture Decision Records (ADRs 001–008)
├── ai-service/                          # Scaffolding for Phase 2 ML components (Planned)
├── infrastructure/                      # Docker and service scaffolding (Planned)
├── event-simulator/                     # Synthetic test scenarios
├── .env.example                         # Environment configuration template (No secrets)
└── README.md
```

---

## Setup & Developer Quickstart

### Prerequisites
- **Node.js**: `>= 18` (Tested on Node v26.5.0)
- **PostgreSQL**: `15+` (Running locally on port 5432 or in Docker)
- **Git**

### 1. Database Setup
```bash
# Connect to PostgreSQL and create primary and test databases:
psql -U postgres -c "CREATE DATABASE sentinelx;"
psql -U postgres -c "CREATE DATABASE sentinelx_test;"

# Apply initial schema, migrations, and seed data:
psql -U postgres -d sentinelx -f database/migrations/001_initial_soc_schema.sql
psql -U postgres -d sentinelx -f database/migrations/002_event_streaming_idempotency_and_dlq.sql
psql -U postgres -d sentinelx -f database/migrations/003_event_correlation_and_candidate_incidents.sql
psql -U postgres -d sentinelx -f database/migrations/004_incident_risk_scoring_and_prioritization.sql
psql -U postgres -d sentinelx -f database/seeds/001_initial_roles_and_admin.sql
```

### 2. Backend Setup
```bash
cd backend

# Copy environment configuration template:
cp ../.env.example .env

# Install dependencies:
npm install

# Compile TypeScript:
npm run build

# Run the test suite:
npm test

# Start the development server:
npm run start:dev
# Or run compiled production bundle:
node dist/main.js
```
The REST API server listens on `http://localhost:4000/api/v1`.  
Health check endpoint: `http://localhost:4000/api/v1/health`.

### 3. Frontend Setup
```bash
cd frontend

# Install dependencies:
npm install

# Verify production build:
npm run build

# Start Vite development server:
npm run dev
```
The analyst dashboard is accessible at `http://localhost:5173`.

---

## Verified Test & Build Evidence

All test and build evidence has been independently executed and verified:

### Backend Test Suite (`npm test`)
```text
$ npm test

> sentinelx-backend@0.1.0 test
> jest --config test/jest-all.json

PASS test/rate-limiting.spec.ts
PASS src/common/health/health.controller.spec.ts
PASS test/schema-integration.spec.ts
PASS test/risk-scoring.spec.ts (10/10 passed)
PASS test/investigation-graph.spec.ts (12/12 passed)
PASS src/detections/dsa/sliding-window-detector.spec.ts
PASS test/streaming-pipeline.spec.ts
PASS test/event-pipeline.spec.ts
PASS test/auth-security.spec.ts
PASS test/correlation-engine.spec.ts
PASS test/investigations.spec.ts (9/9 passed)
PASS test/risk-integration.spec.ts (10/10 passed)

Test Suites: 12 passed, 12 total
Tests:       96 passed, 96 total
Snapshots:   0 total
Time:        6.969 s
Ran all test suites.
```

### Frontend Production Build (`npm run build`)
```text
$ cd frontend && npm run build

> sentinelx-frontend@0.1.0 build
> tsc && vite build

vite v6.4.4 building for production...
✓ 1651 modules transformed.
dist/index.html                   0.57 kB │ gzip:  0.36 kB
dist/assets/index-DxZBT7F5.css   21.93 kB │ gzip:  4.51 kB
dist/assets/index-Dur1F72a.js   250.59 kB │ gzip: 78.27 kB
✓ built in 1.32s
```

---

## Reproducible Benchmarks & Performance Qualifications

### 1. Risk Scoring & Priority Queue Benchmark (`scripts/benchmark-risk.js`)
Evaluates pure mathematical evaluation throughput and Top-K selection performance (Node.js v26.5.0 on macOS ARM64):

```bash
cd backend
node scripts/benchmark-risk.js
```

#### A. Mathematical Scoring Evaluation:
- **Throughput**: **7,375,016 evaluations/sec**
- **Per-Evaluation Latency**: **0.1 µs** (Median 1.374 ms for 10,000 items)

#### B. Top-$K$ Incident Selection ($K = 20$) vs Naive Full Array Quicksort:
| Incidents ($N$) | Min-Heap Top-K ($O(N \log K)$) | Full Array Sort ($O(N \log N)$) | Heap Advantage | Equivalence |
| :--- | :--- | :--- | :--- | :---: |
| **$N = 1,000$** | **$29.7\,\mu\text{s}$** | $144.8\,\mu\text{s}$ | **4.87x faster** | 100% Identical |
| **$N = 10,000$** | **$103.4\,\mu\text{s}$** | $2.131\,\text{ms}$ | **20.61x faster** | 100% Identical |
| **$N = 50,000$** | **$258.7\,\mu\text{s}$** | $12.896\,\text{ms}$ | **49.84x faster** | 100% Identical |

> [!WARNING]
> **Risk Benchmark Qualification:**
> These figures evaluate **pure in-memory algorithmic latency** of the mathematical scoring formula and binary heap data structures. They do **not** reflect end-to-end HTTP REST latency or PostgreSQL relational disk persistence.

---

### 2. Graph Algorithmic Benchmark (`scripts/benchmark-graph.js`)
```bash
cd backend
node scripts/benchmark-graph.js
```

| Graph Scale | Nodes / Edges | Construction Median | BFS (Hops=3) Median | DFS Pathfinding Median | Blast Radius Median | Cycle Detection Median |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 100 / 160 | $258.7\,\mu\text{s}$ | $1.3\,\mu\text{s}$ (774k ops/s) | $59.6\,\mu\text{s}$ (15.6k ops/s) | $8.0\,\mu\text{s}$ (105k ops/s) | $35.3\,\mu\text{s}$ (22.5k ops/s) |
| **Medium** | 500 / 664 | $1.113\,\text{ms}$ | $0.2\,\mu\text{s}$ (5.54M ops/s) | $49.3\,\mu\text{s}$ (19.4k ops/s) | $6.5\,\mu\text{s}$ (141k ops/s) | $114.4\,\mu\text{s}$ (7.6k ops/s) |
| **Large** | 1,950 / 2,498 | $4.480\,\text{ms}$ | $0.2\,\mu\text{s}$ (6.54M ops/s) | $3.4\,\mu\text{s}$ (262k ops/s) | $5.4\,\mu\text{s}$ (185k ops/s) | $463.7\,\mu\text{s}$ (2.0k ops/s) |

---

### 3. Correlation Benchmark (`scripts/benchmark-correlation.js`)
```bash
cd backend
node scripts/benchmark-correlation.js
```

| Metric | Indexed CorrelationEngine | Naive Linear Baseline | Advantage |
| :--- | :---: | :---: | :---: |
| **Median Duration** | **62.58 ms** | 2,274.11 ms | **36.34x faster** |
| **Throughput** | **159,794 events/sec** | 4,397 events/sec | — |
| **p50 Latency** | **0.0051 ms** (5.1 µs) | 0.2329 ms | — |

---

## Security Controls

| Security Control | Implementation | Verification |
| :--- | :--- | :--- |
| **Anti-IP-Bleeding** | Source IP carries zero correlation weight ($w = 0.0$) unless reinforced. Direct User-User or Asset-Asset graph edges rejected without correlation anchor. | Tested against shared NAT address (`198.51.100.99`) and in `InvestigationGraph.addEdge()`. |
| **Logarithmic Dampening** | Sublinear curve $\min(1.0, \frac{\ln(1+N)}{\ln(1+50)})$ prevents event flooding from artificially inflating risk scores to infinity. | Tested with 10,000 identical events in `test/risk-scoring.spec.ts`. |
| **Evidence Provenance** | Every graph edge captures `recordType`, `sourceRecordId`, `confidence`, and `timestamp`. | Verified in `test/investigation-graph.spec.ts`. |
| **Pessimistic Row Locking** | Candidate promotion uses `pessimistic_write` row locking via a single-table QueryBuilder inside `dataSource.transaction(...)`. | Tested with 3 simultaneous concurrent promotion requests; exactly 1 incident record created. |
| **Server-Side RBAC** | Controller endpoints enforce `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles()`. | Tested across auth, correlation, investigation, and risk test suites. |
| **Traversal Protection Limits** | API enforces strict ceilings (`maxHops <= 5`, `maxDepth <= 6`, `maxPaths <= 20`, `maxNodes <= 500`). | Verified in `InvestigationQueryDto`. |
| **Audit Logging** | All graph investigations, risk evaluations, promotions, and triages logged via `AuditService`. | Verified in `test/risk-integration.spec.ts` and `test/investigations.spec.ts`. |
| **Zero Secrets in Git** | `.env` ignored; only `.env.example` tracked. | Audited via `git ls-files`. |

---

## Architecture Decision Records (ADRs)

Detailed technical decisions and trade-offs are documented under [`docs/decisions/`](docs/decisions/):
- **[ADR-001](docs/decisions/001-modular-monolith-architecture.md)**: Modular Monolith Architecture
- **[ADR-002](docs/decisions/002-database-schema-and-migrations.md)**: Database Schema & Migration Strategy
- **[ADR-003](docs/decisions/003-deterministic-dsa-detection-engine.md)**: Deterministic DSA Detection Engine ($O(1)$ Amortized)
- **[ADR-004](docs/decisions/004-soc-design-system-and-analyst-ux.md)**: SOC Design System & Analyst UX
- **[ADR-005](docs/decisions/005-kafka-streaming-and-delivery-guarantees.md)**: Kafka Streaming & Delivery Guarantees
- **[ADR-006](docs/decisions/006-event-correlation-and-anti-ip-bleeding.md)**: Multi-Attribute Correlation, Anti-IP-Bleeding Safety & Candidate Incident Lifecycle
- **[ADR-007](docs/decisions/007-graph-investigation-and-blast-radius.md)**: Graph-Based Security Investigation, Attack Path Discovery & Blast-Radius Analysis
- **[ADR-008](docs/decisions/008-explainable-incident-risk-scoring.md)**: Explainable Incident Risk Scoring, Sublinear Dampening & Priority Queue DSA

---

## License

This project is licensed under the Apache 2.0 License.
