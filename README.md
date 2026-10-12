# SentinelX — AI-Assisted Security Operations Center (SOC)

[![Backend Tests](https://img.shields.io/badge/backend%20tests-55%2F55%20passing-brightgreen)](#verified-test--build-evidence)
[![Frontend Build](https://img.shields.io/badge/frontend%20build-passing-brightgreen)](#frontend-production-build)
[![Current Gate](https://img.shields.io/badge/gate-Milestone%202.2%20APPROVED%20WITH%20LIMITATIONS-blue)](#project-status--milestone-gates)
[![Milestone 2.3](https://img.shields.io/badge/milestone%202.3-ON%20HOLD-orange)](#project-status--milestone-gates)

SentinelX is a production-grade, testable Security Operations Center (SOC) platform designed to ingest high-velocity security telemetry, execute deterministic detection rules using algorithmic data structures (DSA), correlate related events into candidate incident clusters without false-positive IP merges, manage full incident lifecycles, and deliver explainable threat intelligence to security analysts.

---

## Project Status & Milestone Gates

| Milestone | Scope | Status | Acceptance Gate Verification |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Foundation, PostgreSQL Schema, Auth, RBAC, Sliding-Window Detector, Analyst UI | **COMPLETED** | Verified at commit `70b1c19` (All criteria met). |
| **Milestone 2.1** | Event Streaming, Idempotency, Dead-Letter Queue (DLQ), Consumer Retry | **COMPLETED** | Verified at commit `bf62c0c` ([ADR-005](docs/decisions/005-kafka-streaming-and-delivery-guarantees.md)). |
| **Milestone 2.2** | Multi-Attribute Correlation Engine, Anti-IP-Bleeding, Candidate Incident Lifecycle | **APPROVED WITH LIMITATIONS** | Verified at commit `55d150b` ([ADR-006](docs/decisions/006-event-correlation-and-anti-ip-bleeding.md)). |
| **Milestone 2.3** | Graph-Based Investigation (BFS/DFS Traversal, Blast Radius, Cycle Detection) | **ON HOLD** | **STRICTLY ON HOLD.** Implementation has not been started. |
| **Milestone 2.4** | Risk Prioritization & Dynamic Asset Criticality Scoring | **PLANNED** | Pending Milestone 2.3 completion. |
| **Milestone 2.5** | Machine Learning Anomaly Detection (Isolation Forest / Autoencoders) | **PLANNED** | Pending Milestone 2.4 completion. |
| **Milestone 2.6** | Evidence-Grounded AI Incident Copilot (RAG over MITRE ATT&CK & Runbooks) | **PLANNED** | Pending Milestone 2.5 completion. |
| **Milestone 2.7** | Real-Time Dashboard WebSocket Streaming | **PLANNED** | Pending Milestone 2.6 completion. |
| **Phase 3** | Enterprise Distributed Deployment, Kubernetes, Full Telemetry | **PLANNED** | Future roadmap. |

> [!IMPORTANT]
> **Milestone 2.3 is currently ON HOLD.** Graph-based entity investigation, BFS/DFS pathfinding, blast-radius calculation, and cycle detection are planned features that have not been started and are not present in the current codebase.

---

## Real-World SOC Use Case

Enterprise SOC environments suffer from severe **alert fatigue** and **false correlation explosion**:
1. **Corporate NAT / VPN Egress Pools**: Thousands of legitimate corporate employees route through shared public IP addresses (e.g. `198.51.100.99`). Naive correlation engines that group alerts solely by source IP erroneously merge disjoint user sessions into massive false-positive incidents ("IP Bleeding").
2. **Volumetric Telemetry vs Processing Latency**: Raw authentication and network telemetry arrives at thousands of events per second. Running unindexed $O(N^2)$ cross-event comparisons causes processing backpressure.
3. **Analyst Explainability**: Correlation decisions must be grounded in observable factors (MITRE ATT&CK progressions, shared identities, shared assets) with mathematical weights rather than opaque "black-box" scores.

SentinelX solves these challenges with:
- **Strict Anti-IP-Bleeding Safeguards**: An IP address is assigned a weight of 0.0 unless anchored by a shared identity, destination asset, or valid kill-chain progression.
- **Inverted-Index Correlation**: In-memory hash indexing (`userIndex`, `assetIndex`) provides sub-millisecond candidate cluster lookup ($O(1)$ amortized).
- **Candidate Incident Lifecycle**: Hypotheses are isolated as `CANDIDATE` incidents, requiring analyst review or threshold crossing before promotion to confirmed `INC-xxxx` operational records.
- **Transactional Row Locking**: Prevents race conditions during concurrent promotion requests via PostgreSQL `pessimistic_write` row locking.

---

## System Architecture

```
                      +-----------------------------+
                      |     React / Vite Frontend   |
                      |   (Enterprise SOC Console)  |
                      |  - Health Polling (10s)     |
                      |  - Incident Queue Table     |
                      |  - Incident Detail Modal    |
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
| **Modular Monolith Backend** | **Implemented** | NestJS with domain modules (`auth`, `users`, `events`, `detections`, `incidents`, `audit`, `streaming`, `correlation`, `health`). | `npm test` (55 tests passing) |
| **PostgreSQL Schema & Migrations** | **Implemented** | Reversible migrations `001`, `002`, `003` with foreign keys, check constraints, and compound indexes. | `scripts/test-migration-rollback.js` |
| **Authentication & RBAC** | **Implemented** | JWT access tokens, bcrypt password hashing, server-side `@Roles()` decorator, and `RolesGuard`. | `test/auth-security.spec.ts` |
| **Deterministic DSA Detector** | **Implemented** | In-memory sliding-window deque for brute-force pattern matching ($O(1)$ amortized insertion and eviction). | `sliding-window-detector.spec.ts` |
| **Event Streaming & Retries** | **Implemented** | Dual-mode streaming module: built-in in-memory broker with 3 partitions, idempotency key deduplication, and DLQ persistence. External Kafka configurable via env. | `test/streaming-pipeline.spec.ts` |
| **Multi-Attribute Correlation Engine** | **Implemented** | Inverted hash-indexed candidate clustering, anti-IP-bleeding safeguard ($w_{\text{IP}} = 0$ unanchored), calibrated weights summing to $1.000$, and explainability factors. | `test/correlation-engine.spec.ts` |
| **Candidate Incident Lifecycle** | **Implemented** | Separate `candidate_incidents` table, status transitions (`CANDIDATE`, `PROMOTED`, `DISMISSED`), idempotent promotion, PostgreSQL row locking (`pessimistic_write`). | `test/correlation-engine.spec.ts` |
| **Enterprise SOC Frontend** | **Implemented** | React 18, TypeScript, Vite, Tailwind CSS. Displays backend health badge, metrics cards, paginated incident queue, and telemetry detail modal. | `tsc && vite build` (0 errors) |
| **Graph-Based Investigation** | **ON HOLD** | Entity graph modeling, BFS/DFS traversal, blast-radius calculation, cycle detection. **Not started.** | Milestone 2.3 (Paused) |
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
│   │   ├── streaming/                   # Dual-mode streaming broker, idempotency & DLQ
│   │   ├── users/                       # User and role entities
│   │   ├── app.module.ts                # Root application module
│   │   └── main.ts                      # Bootstrap entry point (Helmet, CORS, ValidationPipe)
│   └── test/                            # Integration test suites (Jest)
├── frontend/
│   ├── src/
│   │   ├── app/                         # Main App component & layout
│   │   ├── components/                  # Header, MetricCard, and UI components
│   │   ├── features/                    # Auth form, IncidentQueue, and detail modal
│   │   ├── services/                    # Axios API client
│   │   └── types/                       # TypeScript interfaces
│   ├── package.json
│   └── vite.config.ts
├── database/
│   ├── migrations/                      # Reversible PostgreSQL migrations (001, 002, 003)
│   └── seeds/                           # Default roles and test users
├── docs/
│   └── decisions/                       # Architecture Decision Records (ADRs 001–006)
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
| **SOC Analyst** | `analyst@sentinelx.local` | `AnalystPassword123!` | Read/triage incidents, inspect events |
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

All test and build evidence has been independently executed and verified against commit `55d150b`:

### Backend Test Suite (`npm test`)
```text
$ npm test

> sentinelx-backend@0.1.0 test
> jest --config test/jest-all.json

PASS src/detections/dsa/sliding-window-detector.spec.ts
PASS src/common/health/health.controller.spec.ts
PASS test/schema-integration.spec.ts
PASS test/rate-limiting.spec.ts
PASS test/event-pipeline.spec.ts
PASS test/streaming-pipeline.spec.ts
PASS test/auth-security.spec.ts
PASS test/correlation-engine.spec.ts

Test Suites: 8 passed, 8 total
Tests:       55 passed, 55 total
Snapshots:   0 total
Time:        6.663 s
Ran all test suites.
```

### Frontend Production Build (`npm run build`)
```text
$ cd frontend && npm run build

> sentinelx-frontend@0.1.0 build
> tsc && vite build

vite v6.4.4 building for production...
✓ 1649 modules transformed.
dist/index.html                   0.57 kB │ gzip:  0.37 kB
dist/assets/index-CRXWZPyl.css   17.32 kB │ gzip:  3.88 kB
dist/assets/index-CqfKOmGp.js   218.88 kB │ gzip: 72.31 kB
✓ built in 1.17s
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

## Correlation Benchmark Methodology & Qualifications

SentinelX includes a reproducible benchmark comparing the in-memory inverted-index correlation engine against an equivalent linear-scan baseline.

### Execution Command:
```bash
cd backend
node scripts/benchmark-correlation.js
```

### Methodology:
- **Workload**: Deterministic Linear Congruential Generator (LCG, Seed = 42) producing 10,000 security events with 300 distinct users, 150 IP addresses, and 50 assets.
- **Equivalence Verification**: Before timing, both implementations process all 10,000 events to verify 100% identical cluster counts (2,511 clusters formed on both) and identical correlation decisions.
- **Timing Protocol**: 1,000 warm-up events followed by 5 measured iterations using high-resolution timers (`process.hrtime.bigint()`).

### Observed Benchmark Metrics ($N = 10,000$ Events):
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
> **Crucial Benchmark Qualification:**  
> The reported **36.34x speedup** and **~160,000 events/sec throughput** apply **strictly to in-memory algorithmic indexing** of active candidate clusters.  
> It does **not** represent end-to-end HTTP/PostgreSQL ingestion throughput in production, which is bounded by synchronous disk I/O and database transactions (~200–350 events/sec for single-row synchronous persistence).

---

## Security Controls

| Security Control | Implementation | Verification |
| :--- | :--- | :--- |
| **Anti-IP-Bleeding** | Source IP carries zero correlation weight ($w = 0.0$) unless reinforced by an identity, asset, or MITRE progression anchor. | Tested against shared NAT address (`198.51.100.99`) across distinct users. |
| **Pessimistic Row Locking** | Candidate promotion uses `pessimistic_write` row locking via a single-table QueryBuilder inside `dataSource.transaction(...)`. | Tested with 3 simultaneous concurrent promotion requests; exactly 1 incident record created. |
| **Server-Side RBAC** | Controller endpoints enforce `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles()`. | Tested with `READ_ONLY_AUDITOR` getting 403 Forbidden on mutations and 401 on unauthenticated requests. |
| **Password Hashing** | Bcrypt with salt rounds = 10. | Tested in `test/auth-security.spec.ts`. |
| **Input Validation** | Global `ValidationPipe` with `whitelist: true`, `forbidNonWhitelisted: true`, and `transform: true`. | Verified on all DTOs. |
| **Rate Limiting** | NestJS Throttler (`100 req / 60s`). | Verified in `test/rate-limiting.spec.ts`. |
| **HTTP Security Headers** | Helmet middleware enabled on all responses. | Verified in `main.ts`. |
| **Zero Secrets in Git** | `.env` ignored; only `.env.example` tracked. | Audited via `git ls-files`. |

---

## Known Limitations & Architectural Trade-Offs

The following limitations are explicitly documented as current architectural constraints under **Milestone 2.2 — APPROVED WITH DOCUMENTED LIMITATIONS**:

1. **In-Memory Cluster State**: Active candidate cluster state is currently stored in Node.js process heap memory. While factor history is bounded to the latest 10 items (`slice(-10)`) and sliding-window eviction purges stale clusters, high-volume production deployments with millions of distinct entities per hour should back this state with an external distributed cache (e.g. Redis sliding-window sorted sets).
2. **Ingestion I/O Bottleneck**: Synchronous single-event HTTP ingestion persists directly to PostgreSQL, capping ingestion at ~200–350 events/sec. Bulk batching or streaming ingestion through Kafka consumer workers is required for high-throughput enterprise pipelines.
3. **Sliding Window Boundary**: Events arriving with timestamps older than $t - W$ ($W = 15\text{ minutes}$) after cluster eviction will initiate a new candidate incident cluster rather than merging into the evicted one. This is by design for temporal correlation windows.
4. **Milestone 2.3 Paused**: Graph-based investigation, BFS/DFS pathfinding, and cycle detection are not yet implemented.

---

## Architecture Decision Records (ADRs)

Detailed technical decisions and trade-offs are documented under [`docs/decisions/`](docs/decisions/):
- **[ADR-001](docs/decisions/001-modular-monolith-architecture.md)**: Modular Monolith Architecture
- **[ADR-002](docs/decisions/002-database-schema-and-migrations.md)**: Database Schema & Migration Strategy
- **[ADR-003](docs/decisions/003-deterministic-dsa-detection-engine.md)**: Deterministic DSA Detection Engine ($O(1)$ Amortized)
- **[ADR-004](docs/decisions/004-soc-design-system-and-analyst-ux.md)**: SOC Design System & Analyst UX
- **[ADR-005](docs/decisions/005-kafka-streaming-and-delivery-guarantees.md)**: Kafka Streaming & Delivery Guarantees
- **[ADR-006](docs/decisions/006-event-correlation-and-anti-ip-bleeding.md)**: Multi-Attribute Correlation, Anti-IP-Bleeding Safety & Candidate Incident Lifecycle

---

## License

This project is licensed under the Apache 2.0 License.
