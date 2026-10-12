const { CorrelationEngine } = require('../dist/correlation/correlation.engine');
const { DEFAULT_CORRELATION_CONFIG } = require('../dist/correlation/correlation.types');

/**
 * Baseline Naive Full-Rescan Correlation
 * Scans ALL prior events in linear history O(N) per incoming event -> O(N^2) total
 */
class NaiveRescanBaseline {
  constructor() {
    this.clusters = [];
  }

  ingest(event) {
    let matchedCluster = null;
    let bestScore = 0;

    // Linear rescan across ALL existing clusters (unindexed)
    for (const cluster of this.clusters) {
      let score = 0;
      if (cluster.primaryUser && event.targetUser && cluster.primaryUser.toLowerCase() === event.targetUser.toLowerCase()) {
        score += 0.35;
      }
      if (cluster.primarySourceIp && event.sourceIp && cluster.primarySourceIp === event.sourceIp) {
        if (score > 0) score += 0.15;
      }
      if (score >= 0.50 && score > bestScore) {
        bestScore = score;
        matchedCluster = cluster;
      }
    }

    if (matchedCluster) {
      matchedCluster.eventIds.push(event.id);
      matchedCluster.lastSeen = event.eventTimestamp;
    } else {
      matchedCluster = {
        id: `naive-${this.clusters.length + 1}`,
        primaryUser: event.targetUser,
        primarySourceIp: event.sourceIp,
        eventIds: [event.id],
        firstSeen: event.eventTimestamp,
        lastSeen: event.eventTimestamp,
      };
      this.clusters.push(matchedCluster);
    }
    return matchedCluster;
  }
}

function generateEvents(count) {
  const events = [];
  const baseTime = Date.now() - 3600000; // 1 hour ago
  const users = Array.from({ length: 500 }, (_, i) => `user_${i}@sentinelx.local`);
  const ips = Array.from({ length: 200 }, (_, i) => `192.168.${Math.floor(i / 250)}.${(i % 250) + 1}`);
  const eventTypes = ['AUTH_FAILURE', 'AUTH_SUCCESS', 'PRIVILEGE_ESCALATION', 'PORT_SCAN'];

  for (let i = 0; i < count; i++) {
    const user = users[i % users.length];
    const ip = ips[i % ips.length];
    const eventType = eventTypes[i % eventTypes.length];
    const timestamp = new Date(baseTime + i * 500); // 500ms apart

    events.push({
      id: `evt-${i + 1}`,
      eventType,
      severity: 'MEDIUM',
      sourceIp: ip,
      targetUser: user,
      rawPayload: {},
      normalizedDetails: {},
      eventTimestamp: timestamp,
    });
  }
  return events;
}

function calculatePercentiles(latencies) {
  latencies.sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];
  return { p50, p95, p99 };
}

async function runBenchmark() {
  const EVENT_COUNT = 20000;
  console.log(`================================================================`);
  console.log(` SENTINELX CORRELATION BENCHMARK (N = ${EVENT_COUNT} events)`);
  console.log(` Comparing Incremental Indexing vs Naive Full-Rescan Baseline`);
  console.log(`================================================================\n`);

  const events = generateEvents(EVENT_COUNT);

  // 1. Benchmark Incremental CorrelationEngine (with inverted index)
  console.log(`[1/2] Running Incremental CorrelationEngine...`);
  const engine = new CorrelationEngine(DEFAULT_CORRELATION_CONFIG);
  const incLatencies = [];

  const incStart = process.hrtime.bigint();
  for (const event of events) {
    const t0 = process.hrtime.bigint();
    engine.ingest(event);
    const t1 = process.hrtime.bigint();
    incLatencies.push(Number(t1 - t0) / 1e6); // ms
  }
  const incEnd = process.hrtime.bigint();
  const incTotalMs = Number(incEnd - incStart) / 1e6;
  const incThroughput = (EVENT_COUNT / (incTotalMs / 1000)).toFixed(2);
  const incP = calculatePercentiles(incLatencies);

  // 2. Benchmark Naive Full-Rescan Baseline
  console.log(`[2/2] Running Naive Full-Rescan Baseline...`);
  const naive = new NaiveRescanBaseline();
  const naiveLatencies = [];

  const naiveStart = process.hrtime.bigint();
  for (const event of events) {
    const t0 = process.hrtime.bigint();
    naive.ingest(event);
    const t1 = process.hrtime.bigint();
    naiveLatencies.push(Number(t1 - t0) / 1e6); // ms
  }
  const naiveEnd = process.hrtime.bigint();
  const naiveTotalMs = Number(naiveEnd - naiveStart) / 1e6;
  const naiveThroughput = (EVENT_COUNT / (naiveTotalMs / 1000)).toFixed(2);
  const naiveP = calculatePercentiles(naiveLatencies);

  const speedup = (naiveTotalMs / incTotalMs).toFixed(2);

  console.log(`\n----------------- BENCHMARK RESULTS -----------------`);
  console.table([
    {
      Approach: 'Incremental Engine (Indexed)',
      'Total Time (ms)': incTotalMs.toFixed(2),
      'Throughput (events/s)': incThroughput,
      'p50 (ms)': incP.p50.toFixed(4),
      'p95 (ms)': incP.p95.toFixed(4),
      'p99 (ms)': incP.p99.toFixed(4),
      'Active Clusters': engine.getClusterCount(),
    },
    {
      Approach: 'Naive Full-Rescan Baseline (O(N^2))',
      'Total Time (ms)': naiveTotalMs.toFixed(2),
      'Throughput (events/s)': naiveThroughput,
      'p50 (ms)': naiveP.p50.toFixed(4),
      'p95 (ms)': naiveP.p95.toFixed(4),
      'p99 (ms)': naiveP.p99.toFixed(4),
      'Active Clusters': naive.clusters.length,
    },
  ]);

  console.log(`Performance Advantage: Incremental Engine is ${speedup}x faster than Full-Rescan on N = ${EVENT_COUNT}.\n`);
}

runBenchmark().catch(console.error);
