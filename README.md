# SentinelX — AI-Assisted Security Operations Center (SOC)

SentinelX is a high-performance, testable Security Operations Center platform designed to ingest security telemetry, execute deterministic detection rules using algorithmic data structures (DSA), manage incident lifecycles, and present real-time threat intelligence to security analysts.

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
├── ai-service/           # Python/FastAPI anomaly scoring and threat intel
├── event-simulator/      # Synthetic test telemetry generator
├── infrastructure/       # Docker, Kafka, Prometheus & Grafana configs
├── database/             # PostgreSQL database migrations and seeds
├── docs/                 # Architecture Decision Records (ADRs) and system specs
├── .github/workflows/    # CI pipelines for automated linting and unit testing
├── docker-compose.yml    # Development service containerization
└── README.md
```

## Engineering Milestones

### Phase 1 — Foundation & Core SOC
- [x] **Milestone 1.1**: Repository, modular monolith architecture & professional SOC design system
- [ ] **Milestone 1.2**: PostgreSQL schema, migrations, and database entities
- [ ] **Milestone 1.3**: Authentication, RBAC, session lifecycle, and audit trail
- [ ] **Milestone 1.4**: Security telemetry ingestion, normalization, and persistence
- [ ] **Milestone 1.5**: In-memory DSA sliding-window correlation and incident generation
- [ ] **Milestone 1.6**: Incident detail view, queue triage, and full vertical slice verification

## Quickstart

### Prerequisites
- Node.js >= 18 (Tested on v26.5.0)
- PostgreSQL 15+ (Local instance or Docker)
- Git

### 1. Backend Setup
```bash
cd backend
cp ../.env.example .env
npm install
npm run build
npm run start:dev
```
The API server will listen on `http://localhost:4000/api/v1`. Verify with:
```bash
curl http://localhost:4000/api/v1/health
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
The analyst dashboard will be available at `http://localhost:5173`.

## Architecture Decision Records (ADRs)
Explore our key design decisions under `docs/decisions/`:
- `ADR-001`: Modular Monolith Architecture
- `ADR-002`: Database Schema & Migration Strategy
- `ADR-003`: Deterministic DSA Detection Engine
- `ADR-004`: SOC Design System & Analyst UX
