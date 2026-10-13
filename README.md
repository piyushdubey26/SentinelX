# SentinelX — AI-Assisted Security Operations Center (SOC)

[![Backend Tests](https://img.shields.io/badge/backend%20tests-76%2F76%20passing-brightgreen)](#verified-test--build-evidence)
[![Frontend Build](https://img.shields.io/badge/frontend%20build-passing-brightgreen)](#frontend-production-build)
[![Current Gate](https://img.shields.io/badge/gate-Milestone%202.3%20IMPLEMENTED%20%26%20VERIFIED-brightgreen)](#project-status--milestone-gates)
[![Milestone 2.4](https://img.shields.io/badge/milestone%202.4-ON%20HOLD-orange)](#project-status--milestone-gates)

SentinelX is a production-grade, testable Security Operations Center (SOC) platform designed to ingest high-velocity security telemetry, execute deterministic detection rules using algorithmic data structures (DSA), correlate related events into candidate incident clusters without false-positive IP merges, explore incident relationships using graph traversal algorithms (BFS/DFS, blast-radius analysis, cycle detection), manage full incident lifecycles, and deliver explainable threat intelligence to security analysts.

---

## Project Status & Milestone Gates

| Milestone | Scope | Status | Acceptance Gate Verification |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Foundation, PostgreSQL Schema, Auth, RBAC, Sliding-Window Detector, Analyst UI | **COMPLETED** | Verified at commit `70b1c19` (All criteria met). |
| **Milestone 2.1** | Event Streaming, Idempotency, Dead-Letter Queue (DLQ), Consumer Retry | **COMPLETED** | Verified at commit `bf62c0c` ([ADR-005](docs/decisions/005-kafka-streaming-and-delivery-guarantees.md)). |
| **Milestone 2.2** | Multi-Attribute Correlation Engine, Anti-IP-Bleeding, Candidate Incident Lifecycle | **APPROVED WITH LIMITATIONS** | Verified at commit `55d150b` ([ADR-006](docs/decisions/006-event-correlation-and-anti-ip-bleeding.md)). |
| **Milestone 2.3** | Graph-Based Investigation (In-Memory Adjacency Engine, BFS/DFS, Blast Radius, Cycle Detection, Analyst UI) | **IMPLEMENTED & VERIFIED** | Verified with 21 graph tests passing ([ADR-007](docs/decisions/007-graph-investigation-and-blast-radius.md)). |
| **Milestone 2.4** | Risk Prioritization & Dynamic Asset Criticality Scoring | **ON HOLD** | Strictly on hold pending approval. |
| **Milestone 2.5** | Machine Learning Anomaly Detection (Isolation Forest / Autoencoders) | **PLANNED** | Pending Milestone 2.4 completion. |
| **Milestone 2.6** | Evidence-Grounded AI Incident Copilot (RAG over MITRE ATT&CK & Runbooks) | **PLANNED** | Pending Milestone 2.5 completion. |
| **Milestone 2.7** | Real-Time Dashboard WebSocket Streaming | **PLANNED** | Pending Milestone 2.6 completion. |
| **Phase 3** | Enterprise Distributed Deployment, Kubernetes, Full Telemetry | **PLANNED** | Future roadmap. |

> [!NOTE]
> **Milestone 2.3 is IMPLEMENTED & VERIFIED.** In-memory graph algorithms (BFS, iterative DFS, tiered blast radius, 3-color directed cycle detection), REST APIs with RBAC, and the React analyst investigation interface have been built and tested. Milestone 2.4 remains ON HOLD.

---

## Real-World SOC Use Case

Enterprise SOC environments suffer from severe **alert fatigue**, **false correlation explosion**, and **opaque relationship sprawl**:
1. **Corporate NAT / VPN Egress Pools**: Thousands of legitimate corporate employees route through shared public IP addresses (e.g. `198.51.100.99`). Naive correlation engines that group alerts solely by source IP erroneously merge disjoint user sessions into massive false-positive incidents ("IP Bleeding").
2. **Volumetric Telemetry vs Processing Latency**: Raw authentication and network telemetry arrives at thousands of events per second. Running unindexed $O(N^2)$ cross-event comparisons causes processing backpressure.
3. **Multi-Hop Pivot Discovery**: Disconnected table views obscure how an attacker pivoted from an initial phishing credential compromise through an intermediate jump host to an internal database server.
4. **Analyst Explainability**: Correlation decisions and blast-radius claims must be grounded in observable factors with explicit evidence provenance, distinguishing directly observed facts from inferred relationships.

SentinelX solves these challenges with:
- **Strict Anti-IP-Bleeding Safeguards**: An IP address is assigned a weight of 0.0 unless anchored by a shared identity, destination asset, or valid kill-chain progression. Direct User-to-User or Asset-to-Asset graph edges are rejected without explicit correlation evidence.
- **Inverted-Index Correlation**: In-memory hash indexing (`userIndex`, `assetIndex`) provides sub-millisecond candidate cluster lookup ($O(1)$ amortized).
- **In-Memory Adjacency Investigation Graph**: Evaluates incident topology, BFS multi-hop neighborhood reachability, DFS attack paths, and 3-color directed cycle loops in microseconds without the operational burden of an external graph database.
- **Tiered Blast-Radius Classification**: Differentiates between Tier 1 (Confirmed Directly Observed telemetry) and Tier 2 (Potentially Exposed transitive reachability) with mandatory disclaimer notices.
- **Transactional Row Locking**: Prevents race conditions during concurrent promotion requests via PostgreSQL `pessimistic_write` row locking.

---

## System Architecture

```
                      +-----------------------------+
                      |     React / Vite Frontend   |
                      |   (Enterprise SOC Console)  |
                      |  - Health Polling (10s)     |
                      |  - Incident Queue Table     |
                      |  - Graph Investigation View |
                      |    (Blast Radius, Paths,    |
                      |     Cycles, Topology Table) |
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
                      |  - Blast Radius & Cycles    |
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
| **Modular Monolith Backend** | **Implemented** | NestJS with domain modules (`auth`, `users`, `events`, `detections`, `incidents`, `investigations`, `audit`, `streaming`, `correlation`, `health`). | `npm test` (76 tests passing) |
| **PostgreSQL Schema & Migrations** | **Implemented** | Reversible migrations `001`, `002`, `003` with foreign keys, check constraints, and compound indexes. | `scripts/test-migration-rollback.js` |
| **Authentication & RBAC** | **Implemented** | JWT access tokens, bcrypt password hashing, server-side `@Roles()` decorator, and `RolesGuard`. | `test/auth-security.spec.ts` |
| **Deterministic DSA Detector** | **Implemented** | In-memory sliding-window deque for brute-force pattern matching ($O(1)$ amortized insertion and eviction). | `sliding-window-detector.spec.ts` |
| **Event Streaming & Retries** | **Implemented** | Dual-mode streaming module: built-in in-memory broker with 3 partitions, idempotency key deduplication, and DLQ persistence. External Kafka configurable via env. | `test/streaming-pipeline.spec.ts` |
| **Multi-Attribute Correlation Engine** | **Implemented** | Inverted hash-indexed candidate clustering, anti-IP-bleeding safeguard ($w_{\text{IP}} = 0$ unanchored), calibrated weights summing to $1.000$, and explainability factors. | `test/correlation-engine.spec.ts` |
| **Candidate Incident Lifecycle** | **Implemented** | Separate `candidate_incidents` table, status transitions (`CANDIDATE`, `PROMOTED`, `DISMISSED`), idempotent promotion, PostgreSQL row locking (`pessimistic_write`). | `test/correlation-engine.spec.ts` |
| **Graph-Based Security Investigation** | **Implemented** | In-memory adjacency list (`InvestigationGraph`), BFS ($O(V+E)$), iterative DFS attack-path finding, tiered blast radius, 3-color directed cycle detection, REST endpoints with RBAC & audit logging. | `test/investigation-graph.spec.ts`, `test/investigations.spec.ts` (21 tests) |
| **Enterprise SOC Frontend** | **Implemented** | React 18, TypeScript, Vite, Tailwind CSS. Displays backend health badge, metrics cards, incident queue, and multi-tab Graph Investigation modal. | `tsc && vite build` (0 errors) |
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
│   │   ├── test-migration-rollback.js    # Disposable DB migration forward/down test
│   │   └── setup-db.js                  # Database initialization script
│   ├── src/
│   │   ├── audit/                       # Audit logging module
│   │   ├── auth/                        # JWT authentication, guards, and decorators
│   │   ├── common/                      # Health controller, filters, and interceptors
│   │   ├── config/                      # Database and application configuration
│   │   ├── correlation/                 # Multi-attribute correlation engine & candidate lifecycle
│   │   │   ├── dto/                     # Input validation DTOs
│   │   │   ├── entities/                # CandidateIncident entity
│   │   │   ├── correlation.controller.ts# REST API endpoints with RBAC
│   │   │   ├── correlation.engine.ts    # Inverted-index DSA clustering algorithm
│   │   │   ├── correlation.service.ts   # Transactional persistence & row locking
│   │   │   └── correlation.types.ts     # Domain enums, weights rubric, and interfaces
│   │   ├── detections/                  # DSA sliding-window brute-force detector
│   │   ├── events/                      # Event ingestion and normalization
│   │   ├── incidents/                   # Confirmed incident lifecycle management
│   │   ├── investigations/              # Graph-based investigation engine & APIs
│   │   │   ├── dto/                     # Traversal query validation DTOs
│   │   │   ├── graph/                   # Core InvestigationGraph & graph.types
│   │   │   ├── graph-builder.service.ts # Relational-to-graph builder service
│   │   │   ├── investigations.controller.ts # REST endpoints with RBAC & auditing
│   │   │   ├── investigations.module.ts # NestJS module definition
│   │   │   └── investigations.service.ts    # Investigation business logic
│   │   ├── streaming/                   # Dual-mode streaming broker, idempotency & DLQ
│   │   ├── users/                       # User and role entities
│   │   ├── app.module.ts                # Root application module
│   │   └── main.ts                      # Bootstrap entry point (Helmet, CORS, ValidationPipe)
│   └── test/                            # Integration and unit test suites (Jest)
├── frontend/
│   ├── src/
│   │   ├── app/                         # Main App component & layout
│   │   ├── components/                  # Header, MetricCard, and UI components
│   │   ├── features/                    # Auth form, IncidentQueue, detail modal, and InvestigationGraphView
│   │   ├── services/                    # Axios API client (includes investigation graph endpoints)
│   │   └── types/                       # TypeScript interfaces (including graph entities)
│   ├── package.json
│   └── vite.config.ts
├── database/
│   ├── migrations/                      # Reversible PostgreSQL migrations (001, 002, 003)
│   └── seeds/                           # Default roles and test users
├── docs/
│   └── decisions/                       # Architecture Decision Records (ADRs 001–007)
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

### 4. Default Seeded Credentials (Local Development Only)
| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@sentinelx.local` | `AdminPassword123!` | Full system administration (`*`) |
| **SOC Analyst** | `analyst@sentinelx.local` | `AnalystPassword123!` | Read/triage incidents, inspect events, graph investigation |
| **Auditor** | `auditor@sentinelx.local` | `AdminPassword123!` | Read-only compliance queries |

---

## Environment Variables (`.env.example`)

The repository includes a template `.env.example`. No real credentials or private keys are committed.

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `4000` | Port for the NestJS API server |
| `NODE_ENV` | `development` | Application environment (`development` / `production`) |
| `API_PREFIX` | `api/v1` | Global REST endpoint route prefix |
| `CORS_ORIGIN` | `http://localhost:5173` | Allowed frontend origin for CORS |
| `DB_HOST` | `localhost` | PostgreSQL database host |
| `DB_PORT` | `5432` | PostgreSQL database port |
| `DB_USERNAME` | `postgres` | PostgreSQL username |
| `DB_PASSWORD` | *(empty string)* | PostgreSQL password |
| `DB_NAME` | `sentinelx` | Application database name |
| `DB_LOGGING` | `false` | Enable TypeORM SQL query logging |
| `DB_SSL` | `false` | Enable SSL for PostgreSQL connection |
| `JWT_SECRET` | *(development placeholder)* | Secret key for signing JWT access tokens |
| `JWT_EXPIRATION` | `3600s` | Access token lifespan (1 hour) |
| `REFRESH_TOKEN_SECRET` | *(development placeholder)* | Secret key for refresh tokens |
| `REFRESH_TOKEN_EXPIRATION`| `604800s` | Refresh token lifespan (7 days) |
| `RATE_LIMIT_TTL` | `60000` | Rate limiting sliding window in ms (60 seconds) |
| `RATE_LIMIT_MAX` | `100` | Maximum requests allowed per window per IP |
| `VITE_API_URL` | `http://localhost:4000/api/v1` | Backend API base URL used by frontend |

---

## Verified Test & Build Evidence

All test and build evidence has been independently executed and verified:

### Backend Test Suite (`npm test`)
```text
$ npm test

> sentinelx-backend@0.1.0 test
> jest --config test/jest-all.json

PASS test/investigation-graph.spec.ts
PASS src/detections/dsa/sliding-window-detector.spec.ts
PASS src/common/health/health.controller.spec.ts
PASS test/rate-limiting.spec.ts
PASS test/event-pipeline.spec.ts
PASS test/streaming-pipeline.spec.ts
PASS test/auth-security.spec.ts
PASS test/schema-integration.spec.ts
PASS test/investigations.spec.ts
PASS test/correlation-engine.spec.ts

Test Suites: 10 passed, 10 total
Tests:       76 passed, 76 total
Snapshots:   0 total
Time:        4.721 s
Ran all test suites.
```

### Frontend Production Build (`npm run build`)
```text
$ cd frontend && npm run build

> sentinelx-frontend@0.1.0 build
> tsc && vite build

vite v6.4.4 building for production...
✓ 1656 modules transformed.
dist/index.html                   0.57 kB │ gzip:  0.37 kB
dist/assets/index-D7Uq0Y4C.css   19.53 kB │ gzip:  4.29 kB
dist/assets/index-BqB1kXWn.js   233.12 kB │ gzip: 76.54 kB
✓ built in 1.20s
```

### Migration Forward and Rollback (`node scripts/test-migration-rollback.js`)
```text
[TEST-MIGRATION] Connecting to sentinelx_test...
[TEST-MIGRATION] Table candidate_incidents exists before rollback: true
[TEST-MIGRATION] Executing down migration (rollback)...
[TEST-MIGRATION] Table candidate_incidents exists after rollback: false
[TEST-MIGRATION] Core tables intact after rollback: true
[TEST-MIGRATION] Re-applying up migration...
[TEST-MIGRATION] Table candidate_incidents exists after re-applying up migration: true
[TEST-MIGRATION] PASS: Migration and rollback verified successfully on test database.
```

---

## Reproducible Benchmarks & Performance Qualifications

### 1. Graph Algorithmic Benchmark (`scripts/benchmark-graph.js`)
Evaluates in-memory adjacency list operations across small, medium, and large synthetic security graph topologies (Node.js v26.5.0 on macOS ARM64):

```bash
cd backend
node scripts/benchmark-graph.js
```

| Graph Scale | Nodes / Edges | Construction Median | BFS (Hops=3) Median | DFS Pathfinding Median | Blast Radius Median | Cycle Detection Median |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 100 / 160 | $282.8\,\mu\text{s}$ | $3.3\,\mu\text{s}$ (297k ops/s) | $61.9\,\mu\text{s}$ (8.6k ops/s) | $17.0\,\mu\text{s}$ (33.8k ops/s) | $33.0\,\mu\text{s}$ (26.4k ops/s) |
| **Medium** | 500 / 664 | $1.087\,\text{ms}$ | $0.2\,\mu\text{s}$ (5.49M ops/s) | $52.3\,\mu\text{s}$ (18.6k ops/s) | $6.5\,\mu\text{s}$ (140k ops/s) | $129.1\,\mu\text{s}$ (7.5k ops/s) |
| **Large** | 1,950 / 2,498 | $4.361\,\text{ms}$ | $0.2\,\mu\text{s}$ (6.32M ops/s) | $3.4\,\mu\text{s}$ (265k ops/s) | $5.6\,\mu\text{s}$ (177k ops/s) | $464.2\,\mu\text{s}$ (1.9k ops/s) |

> [!WARNING]
> **Crucial Graph Benchmark Qualification:**  
> These numbers evaluate **pure in-memory algorithmic latency** of the adjacency list, iterative DFS stack, BFS queue, and 3-color DFS cycle detector.  
> They do **not** reflect end-to-end HTTP REST latency or PostgreSQL relational query overhead.

---

### 2. Correlation Benchmark (`scripts/benchmark-correlation.js`)
Compares the in-memory inverted-index correlation engine against an equivalent linear-scan baseline:

```bash
cd backend
node scripts/benchmark-correlation.js
```

| Metric | Indexed CorrelationEngine | Naive Linear Baseline | Advantage |
| :--- | :---: | :---: | :---: |
| **Median Duration** | **62.58 ms** | 2,274.11 ms | **36.34x faster** |
| **Mean Duration** | **64.25 ± 3.95 ms** | 2,283.28 ± 54.38 ms | — |
| **Throughput** | **159,794 events/sec** | 4,397 events/sec | — |
| **p50 Latency** | **0.0051 ms** (5.1 µs) | 0.2329 ms | — |
| **p95 Latency** | **0.0126 ms** (12.6 µs) | 0.3520 ms | — |
| **p99 Latency** | **0.0164 ms** (16.4 µs) | 0.3830 ms | — |
| **Heap Memory Delta** | **+10.53 MB** | -1.45 MB | — |

> [!WARNING]
> **Correlation Benchmark Qualification:**  
> The reported **36.34x speedup** applies strictly to in-memory algorithmic cluster matching, not full database persistence.

---

## Security Controls

| Security Control | Implementation | Verification |
| :--- | :--- | :--- |
| **Anti-IP-Bleeding** | Source IP carries zero correlation weight ($w = 0.0$) unless reinforced. Direct User-User or Asset-Asset graph edges rejected without correlation anchor. | Tested against shared NAT address (`198.51.100.99`) and in `InvestigationGraph.addEdge()`. |
| **Evidence Provenance** | Every graph edge captures `recordType`, `sourceRecordId`, `confidence`, and `timestamp`. | Verified in `test/investigation-graph.spec.ts`. |
| **Pessimistic Row Locking** | Candidate promotion uses `pessimistic_write` row locking via a single-table QueryBuilder inside `dataSource.transaction(...)`. | Tested with 3 simultaneous concurrent promotion requests; exactly 1 incident record created. |
| **Server-Side RBAC** | Controller endpoints enforce `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles(UserRole.ADMIN, UserRole.ANALYST)`. | Tested in `test/auth-security.spec.ts` and `test/investigations.spec.ts`. |
| **Traversal Protection Limits** | API enforces strict ceilings (`maxHops <= 5`, `maxDepth <= 6`, `maxPaths <= 20`, `maxNodes <= 500`). | Verified in `InvestigationQueryDto` and integration tests. |
| **Password Hashing** | Bcrypt with salt rounds = 10. | Tested in `test/auth-security.spec.ts`. |
| **Input Validation** | Global `ValidationPipe` with `whitelist: true`, `forbidNonWhitelisted: true`, and `transform: true`. | Verified on all DTOs. |
| **Rate Limiting** | NestJS Throttler (`100 req / 60s`). | Verified in `test/rate-limiting.spec.ts`. |
| **HTTP Security Headers** | Helmet middleware enabled on all responses. | Verified in `main.ts`. |
| **Audit Logging** | All graph investigations, promotions, and triages logged via `AuditService`. | Verified in `test/investigations.spec.ts`. |
| **Zero Secrets in Git** | `.env` ignored; only `.env.example` tracked. | Audited via `git ls-files`. |

---

## Known Limitations & Architectural Trade-Offs

1. **In-Memory Graph Construction**: Graph structures are built dynamically from PostgreSQL records on query execution. While fast for individual incident subgraphs ($N < 5,000$ entities), querying global organization-wide graphs across millions of historical events will require distributed graph or analytical storage in future phases.
2. **Ingestion I/O Bottleneck**: Synchronous single-event HTTP ingestion persists directly to PostgreSQL, capping ingestion at ~200–350 events/sec. Bulk batching or streaming ingestion through Kafka consumer workers is required for high-throughput enterprise pipelines.
3. **Sliding Window Boundary**: Events arriving with timestamps older than $t - W$ ($W = 15\text{ minutes}$) after cluster eviction will initiate a new candidate incident cluster rather than merging into the evicted one.
4. **Milestone 2.4 On Hold**: Risk prioritization and dynamic asset criticality scoring remain on hold.

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

---

## License

This project is licensed under the Apache 2.0 License.
