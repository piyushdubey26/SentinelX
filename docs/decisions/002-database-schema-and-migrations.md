# ADR-002: PostgreSQL & Migration-First Database Strategy

## Status
Accepted

## Context
Auto-synchronizing database schemas (`synchronize: true` in TypeORM) is prone to unintended table drops, column renames without data migration, and race conditions during concurrent server startups. Production security platforms demand strict auditability of all schema changes.

## Decision
We enforce a **Migration-First** database management strategy:
1. `synchronize: false` is permanently enforced across all environments (including development).
2. All database changes must be written as explicit, versioned SQL/TypeScript migration files under `database/migrations/` or executed via TypeORM migration runner.
3. Migrations must be reversible (`down()` method implemented) and idempotent where possible.
4. Strict foreign key constraints and targeted composite indexes will be applied to match actual query patterns (e.g. querying incidents by `severity` and `status`, or events by `timestamp` and `source_ip`).

## Consequences
- **Positive**: Zero risk of accidental production data loss, fully auditable schema history in Git, deterministic database states for integration tests.
- **Negative**: Requires engineers to run migration scripts explicitly instead of relying on automatic table creation.
