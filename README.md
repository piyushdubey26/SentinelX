# SentinelX — AI-Assisted Security Operations Center (SOC)

SentinelX is a production-grade, testable Security Operations Center platform designed to ingest security telemetry, execute deterministic detection rules using algorithmic data structures (DSA), manage incident lifecycles, and present real-time threat intelligence to security analysts.

## System Architecture Overview

```
                      +-----------------------------+
                      |     React / Vite Frontend   |
                      |   (Enterprise SOC Console)  |
                      +--------------+--------------+
                                     |
                                REST API
                                     |
                      +--------------v--------------+
                      |    NestJS Modular Monolith  |
                      |  - Auth & RBAC (JWT/Bcrypt) |
                      |  - Event Ingestion Pipeline |
                      |  - In-Memory DSA Engine     |
                      |  - Incident Lifecycle Mgr   |
                      |  - Audit & Security Logging |
                      +--------------+--------------+
                                     |
                        +------------+------------+
                        |                         |
               +--------v-------+        +--------v-------+
               |   PostgreSQL   |        |   AI Service   |
               | (TypeORM / Pg) |        |  (FastAPI / ML)|
               +----------------+        +----------------+
```

## Repository Structure

```
sentinelx/
├── frontend/             # React + TypeScript + Vite + Tailwind CSS dashboard
├── backend/              # NestJS modular monolith with strict domain modules
├── ai-service/           # Python/FastAPI anomaly scoring and threat intel (Phase 2 readiness)
├── event-simulator/      # Synthetic attack generator & latency/throughput benchmarks
├── infrastructure/       # Docker, Kafka, Prometheus & Grafana configs
├── database/             # PostgreSQL database migrations and seeds
├── docs/                 # Architecture Decision Records (ADRs) and system specs
├── .github/workflows/    # CI pipelines for automated linting and unit testing
├── docker-compose.yml    # Development service containerization
└── README.md
```

## Phase 1 — Foundation & Core SOC (COMPLETED & VERIFIED)

- [x] **Milestone 1.1**: Repository, modular monolith architecture & professional SOC design system
- [x] **Milestone 1.2**: PostgreSQL schema, reversible migrations, entities, and constraint tests
- [x] **Milestone 1.3**: Authentication (JWT), bcrypt hashing, server-side RBAC, throttler rate-limiting, and audit logging
- [x] **Milestone 1.4**: Security event ingestion, normalization, in-memory DSA sliding-window detector, and incident creation
- [x] **Milestone 1.5**: React analyst console connected to live backend APIs, pagination, detail modal, and triage controls

---

## Quickstart & Developer Setup

### Prerequisites
- Node.js >= 18 (Tested on v26.5.0)
- PostgreSQL 15+ (Local instance or Docker Compose)
- Git

### 1. Database Setup
```bash
# If running local PostgreSQL:
psql -U postgres -c "CREATE DATABASE sentinelx;"
psql -U postgres -c "CREATE DATABASE sentinelx_test;"
psql -U postgres -d sentinelx -f database/migrations/001_initial_soc_schema.sql
psql -U postgres -d sentinelx -f database/seeds/001_initial_roles_and_admin.sql

# Or using Docker:
docker compose up -d postgres
```

### 2. Backend Setup
```bash
cd backend
cp ../.env.example .env
npm install
npm run build
npm test
npm run start:dev
```
API server listens on `http://localhost:4000/api/v1`.

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run build
npm run dev
```
Analyst dashboard is accessible at `http://localhost:5173`.

Default seeded credentials:
- **Admin**: `admin@sentinelx.local` / `AdminPassword123!`
- **SOC Analyst**: `analyst@sentinelx.local` / `AnalystPassword123!`

---

## Running Automated Scenarios & Benchmarks

From the `event-simulator` directory (with backend running):
```bash
# 1. Simulate 5-attempt brute-force attack to trigger detection:
cd backend && npx ts-node ../event-simulator/scenarios/brute_force_attack.ts

# 2. Run ingestion throughput & latency benchmark (100 events):
cd backend && npx ts-node ../event-simulator/tests/benchmark_ingestion.ts
```

### Verified Benchmark Baseline
- **Ingestion Throughput**: ~342.5 events/second
- **Mean Latency**: 2.92 ms
- **p95 Latency**: 5.0 ms
- **Detection Processing Time**: < 0.2 ms (in-memory sliding window deque)

---

## Architecture Decision Records (ADRs)
Explore our key design decisions under `docs/decisions/`:
- `ADR-001`: Modular Monolith Architecture
- `ADR-002`: Database Schema & Migration Strategy
- `ADR-003`: Deterministic DSA Detection Engine ($O(1)$ Amortized)
- `ADR-004`: SOC Design System & Analyst UX
