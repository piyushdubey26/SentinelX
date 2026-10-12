# ADR-005: Event Streaming Architecture, Delivery Semantics & Consistency Strategy

## Status
Accepted

## Context
In a Security Operations Center (SOC) processing high-velocity telemetry (system logins, firewall logs, endpoint processes), direct synchronous HTTP writes to a relational database create database contention, high ingestion latency, and risk dropped events during database maintenance or traffic spikes. Furthermore, distributed message brokers provide *at-least-once* message delivery, meaning network partitions or consumer restarts can deliver identical messages multiple times.

## Decisions

### 1. Delivery Guarantees: Effectively Exactly-Once State Mutation
We recognize that Kafka alone does **not** provide end-to-end exactly-once delivery across decoupled downstream systems (PostgreSQL, in-memory state, and external integrations) without explicit transactional coordination:
- **Broker Semantics**: At-least-once delivery with partition-ordered message offsets.
- **Consumer Idempotency**: Consumers implement dual-tier deduplication:
  1. **In-Memory LRU Cache**: $O(1)$ fast check against the last 50,000 processed keys.
  2. **PostgreSQL Atomic Claim**: Unique constraint on `idempotency_keys(key)` table. Duplicate messages are immediately acknowledged and dropped before mutating `security_events` or triggering detection rules.

### 2. Event Partitioning & Ordering
- **Partition Key**: Set to the SHA-256 event fingerprint (`idempotencyKey`).
- **Ordering Guarantee**: Telemetry from the same correlation entity is pinned to the same partition, guaranteeing strict chronological order per source.

### 3. Resilience, Retries & Dead Letter Queue (DLQ)
- **Transient Failures**: Handled via exponential backoff (attempt 1: immediate, attempt 2: $50\text{ ms} + \text{jitter}$, attempt 3: $100\text{ ms} + \text{jitter}$).
- **Permanent Poison Pills**: Malformed or unrecoverable payloads route directly to `security.events.dlq` topic and `dead_letter_events` table for forensic triage and operator replay.

### 4. Dual-Mode Driver (Hybrid Kafka / Embedded Driver)
- **Production / Staging**: Connects to distributed Kafka brokers via `kafkajs` using environment configuration (`KAFKA_BROKERS`).
- **Development & CI**: Automatically defaults to `EmbeddedStreamingDriver`, an in-memory partitioned queue with offset tracking and consumer groups, ensuring zero-dependency testability.

## Consequences
- **Positive**: Resilient decoupled ingestion, sub-10ms producer response time, zero lost events under database spikes, fully testable without external broker daemon.
- **Negative**: Consumer lag must be actively monitored to detect slow processing pipelines.
