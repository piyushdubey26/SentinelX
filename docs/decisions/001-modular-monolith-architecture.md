# ADR-001: Modular Monolith Architecture for SentinelX Backend

## Status
Accepted

## Context
SentinelX requires high throughput for event ingestion, predictable response latency for analyst querying, and strict transactional consistency for incident lifecycle management. In many greenfield systems, teams split early into microservices, resulting in network serialization overhead, distributed transaction complexities, and difficult local developer onboarding.

## Decision
We adopt a **Modular Monolith** architecture implemented using NestJS with strict module boundaries.
Key principles:
1. All domain areas (`auth`, `users`, `assets`, `events`, `detections`, `incidents`, `risk`, `audit`) are encapsulated within dedicated NestJS modules.
2. In-process communication across modules occurs via strongly typed interfaces, services, and EventEmitter patterns, avoiding HTTP/gRPC overhead between internal components.
3. Controllers remain thin; domain logic resides exclusively inside stateless services.
4. If future scale requires extracting high-throughput ingestion or AI services into separate deployments, module boundaries already isolate the domain models cleanly.

## Consequences
- **Positive**: Single codebase, instant cross-module refactoring with TypeScript, zero network latency between detection and incident triage, straightforward CI/CD.
- **Negative**: Monolithic deployment artifact; memory leaks or high compute in one service can impact the process (mitigated via modular unit testing and memory profiling).
