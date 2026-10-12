# SentinelX System Architecture

## Core Components

1. **Frontend (`/frontend`)**
   - React 18+ with TypeScript, Vite, and Tailwind CSS.
   - Provides views for Incident Queue, Threat Event Stream, Asset Inventory, Risk Scoring, and Audit Trails.

2. **Backend (`/backend`)**
   - NestJS modular monolith running on Node.js.
   - Domain modules:
     - `AuthModule`: JWT-based authentication, password hashing with bcrypt, role-based access control (RBAC).
     - `EventsModule`: Ingests, validates, and normalizes security events.
     - `DetectionsModule`: Evaluates incoming events against deterministic DSA sliding-window rules.
     - `IncidentsModule`: Creates, updates, assigns, and triages incident lifecycles.
     - `AuditModule`: Records immutable audit logs for all security-sensitive analyst actions.
     - `CommonModule`: Global filters, interceptors, health checks, and logging.

3. **Database (`/database` & PostgreSQL)**
   - Schema managed via TypeORM migrations.
   - Tables: `users`, `roles`, `assets`, `security_events`, `detections`, `incidents`, `audit_logs`.

4. **Event Simulator (`/event-simulator`)**
   - Generates synthetic security event streams (e.g. brute force, privilege escalation, data exfiltration) for automated testing.
