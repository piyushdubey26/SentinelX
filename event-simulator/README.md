# SentinelX Event Simulator

Automated synthetic security event generator and performance benchmark tool for SentinelX.

## Prerequisites
Ensure the SentinelX backend is running on `http://localhost:4000/api/v1`.

## Usage

### 1. Brute Force Scenario
Simulates 5 failed authentication attempts within a 60-second window to verify deterministic detection and incident creation:
```bash
npx ts-node scenarios/brute_force_attack.ts
```

### 2. Ingestion Benchmark
Measures baseline HTTP ingestion throughput, p50, p95, and p99 latencies:
```bash
npx ts-node tests/benchmark_ingestion.ts
```
