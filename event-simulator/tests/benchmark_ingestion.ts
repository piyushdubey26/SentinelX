/**
 * SentinelX Ingestion Latency & Throughput Benchmark
 * Measures baseline response latency and events/sec throughput over 100 synthetic events.
 */

import axios from 'axios';

const API_URL = process.env.API_URL || 'http://localhost:4000/api/v1';
const BATCH_SIZE = 100;

async function benchmark() {
  console.log(`[BENCHMARK] Connecting to ${API_URL}...`);
  const loginRes = await axios.post(`${API_URL}/auth/login`, {
    email: 'admin@sentinelx.local',
    password: 'AdminPassword123!',
  });
  const token = loginRes.data.accessToken;
  const headers = { Authorization: `Bearer ${token}` };

  console.log(`[BENCHMARK] Commencing ingestion of ${BATCH_SIZE} events...`);
  const latencies: number[] = [];
  const overallStart = Date.now();

  for (let i = 0; i < BATCH_SIZE; i++) {
    const start = Date.now();
    await axios.post(
      `${API_URL}/events/ingest`,
      {
        eventType: 'AUTH_FAILURE',
        sourceIp: `10.200.0.${(i % 20) + 1}`,
        targetUser: `user_${i}`,
        rawPayload: { iteration: i },
      },
      { headers },
    );
    latencies.push(Date.now() - start);
  }

  const overallDurationMs = Date.now() - overallStart;
  const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  latencies.sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];
  const throughput = ((BATCH_SIZE / overallDurationMs) * 1000).toFixed(2);

  console.log(`===============================================`);
  console.log(`SENTINELX BASELINE INGESTION BENCHMARK RESULTS`);
  console.log(`===============================================`);
  console.log(`Total Events Ingested : ${BATCH_SIZE}`);
  console.log(`Total Duration        : ${overallDurationMs} ms`);
  console.log(`Throughput            : ${throughput} events/sec`);
  console.log(`Mean Ingestion Latency: ${avgLatency.toFixed(2)} ms`);
  console.log(`p50 Latency           : ${p50} ms`);
  console.log(`p95 Latency           : ${p95} ms`);
  console.log(`p99 Latency           : ${p99} ms`);
  console.log(`===============================================`);
}

benchmark().catch(console.error);
