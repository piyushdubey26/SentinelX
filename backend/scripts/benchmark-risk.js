#!/usr/bin/env node

/**
 * SentinelX Milestone 2.4 - Incident Risk Scoring & Priority Queue Benchmark
 * 
 * Evaluates:
 * 1. Mathematical Risk Scoring Throughput (sublinear dampening, recency decay, impact/confidence separation)
 * 2. Algorithmic Complexity Comparison:
 *    - Bounded Min-Heap Top-K Selection: O(N log K) time, O(K) space
 *    - Naive Full-Array QuickSort: O(N log N) time, O(N) space
 * 
 * Scales Evaluated:
 * - N = 1,000 incidents   (K = 20)
 * - N = 10,000 incidents  (K = 20)
 * - N = 50,000 incidents  (K = 20)
 * 
 * Uses deterministic pseudo-random number generator (LCG seed = 7777).
 */

const { RiskPriorityQueue } = require('../dist/risk/dsa/priority-queue');
const { DEFAULT_RISK_CONFIG } = require('../dist/risk/risk.types');

/**
 * Deterministic Linear Congruential Generator (LCG)
 */
class DeterministicPRNG {
  constructor(seed = 7777) {
    this.seed = seed;
  }
  next() {
    this.seed = (this.seed * 1664525 + 1013904223) % 4294967296;
    return this.seed / 4294967296;
  }
  nextInt(min, max) {
    return Math.floor(this.next() * (max - min)) + min;
  }
  pick(arr) {
    return arr[this.nextInt(0, arr.length)];
  }
}

/**
 * Statistical utility functions
 */
function stats(measurements) {
  if (measurements.length === 0) return { min: 0, max: 0, mean: 0, median: 0, p95: 0 };
  const sorted = [...measurements].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = sum / sorted.length;
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const median = sorted[Math.floor(sorted.length / 2)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  return { min, max, mean, median, p95 };
}

function formatDuration(ms) {
  return ms < 1 ? `${(ms * 1000).toFixed(1)} µs` : `${ms.toFixed(3)} ms`;
}

/**
 * Pure evaluation function for benchmark simulation
 */
function evaluateRiskBenchmark(item, config = DEFAULT_RISK_CONFIG) {
  const { weights } = config;
  const rawImpact =
    weights.impactSeverityWeight * item.severityScore +
    weights.impactCriticalityWeight * (item.assetCriticalityScore * item.envModifier) +
    weights.impactBlastRadiusWeight * item.blastRadiusScore;
  const impactScore = Math.min(100.0, Math.max(0.0, rawImpact * 100.0));

  const velocityScore = Math.min(
    1.0,
    Math.log(1 + item.eventCount) / Math.log(1 + weights.velocitySaturationCount),
  );

  const confidenceScore =
    weights.confidenceCorrelationWeight * item.correlationScore +
    weights.confidenceVelocityWeight * velocityScore +
    weights.confidenceDetectionWeight * item.detectionFidelityScore;

  const lambda = Math.LN2 / weights.temporalHalfLifeHours;
  const rawDecay = Math.exp(-lambda * item.elapsedHours);
  const decayMultiplier = Math.max(weights.temporalDecayFloor, rawDecay);

  const confidenceMultiplier = 0.30 + 0.70 * confidenceScore;
  return parseFloat((impactScore * confidenceMultiplier * decayMultiplier).toFixed(2));
}

function runBenchmark() {
  console.log('='.repeat(80));
  console.log('SENTINELX MILESTONE 2.4: RISK SCORING & PRIORITY QUEUE BENCHMARK');
  console.log('='.repeat(80));
  console.log(`Node.js Version: ${process.version}`);
  console.log(`OS: ${process.platform} ${process.arch}`);
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log('Scope: Mathematical evaluation throughput and O(N log K) Heap vs O(N log N) Sort');
  console.log('-'.repeat(80));

  const prng = new DeterministicPRNG(7777);

  // -------------------------------------------------------------------------
  // 1. Throughput: Risk Evaluation Calculation
  // -------------------------------------------------------------------------
  console.log('\n>>> Part 1: Risk Scoring Evaluation Throughput (N = 10,000 evaluations)');
  const sampleItems = [];
  for (let i = 0; i < 10000; i++) {
    sampleItems.push({
      severityScore: prng.pick([0.1, 0.25, 0.5, 0.75, 1.0]),
      assetCriticalityScore: prng.pick([0.25, 0.5, 0.75, 1.0]),
      envModifier: prng.pick([0.7, 0.85, 1.0]),
      blastRadiusScore: prng.pick([0.1, 0.25, 0.5, 0.8]),
      correlationScore: prng.next(),
      eventCount: prng.nextInt(1, 2000),
      detectionFidelityScore: prng.pick([0.75, 0.9, 1.0]),
      elapsedHours: prng.next() * 72.0,
    });
  }

  // Warmup
  for (let i = 0; i < 2000; i++) evaluateRiskBenchmark(sampleItems[i]);

  const evalTimes = [];
  for (let iter = 0; iter < 10; iter++) {
    const t0 = performance.now();
    for (let i = 0; i < 10000; i++) {
      evaluateRiskBenchmark(sampleItems[i]);
    }
    const t1 = performance.now();
    evalTimes.push(t1 - t0);
  }
  const evalStats = stats(evalTimes);
  const evalThroughput = ((10000 / evalStats.mean) * 1000).toFixed(0);
  console.log(`  Batch duration (10k items): Median: ${formatDuration(evalStats.median)} | P95: ${formatDuration(evalStats.p95)}`);
  console.log(`  Throughput:                 ${evalThroughput} evaluations/sec`);
  console.log(`  Per-evaluation latency:     ${formatDuration(evalStats.median / 10000)}`);

  // -------------------------------------------------------------------------
  // 2. Algorithmic Comparison: Top-K PriorityQueue vs Full Array Sort
  // -------------------------------------------------------------------------
  console.log('\n>>> Part 2: Top-K Incident Selection Benchmark (K = 20)');
  const K = 20;
  const scales = [1000, 10000, 50000];

  for (const N of scales) {
    console.log(`\n  --- Workload: N = ${N.toLocaleString()} incidents (Select Top ${K}) ---`);

    // Generate N entries with simulated risk scores
    const entries = [];
    for (let i = 0; i < N; i++) {
      entries.push({
        item: `INC-${1000 + i}`,
        priority: prng.next() * 100.0,
      });
    }

    // A. Equivalence Check
    const heapTopK = RiskPriorityQueue.topK(entries, K);
    const sortedTopK = [...entries]
      .sort((a, b) => b.priority - a.priority)
      .slice(0, K)
      .map((x) => x.item);

    let identical = heapTopK.length === sortedTopK.length;
    for (let i = 0; i < heapTopK.length; i++) {
      if (heapTopK[i] !== sortedTopK[i]) {
        identical = false;
        break;
      }
    }
    console.log(`  Equivalence Verification:  ${identical ? 'PASS (100% Identical Output)' : 'FAIL'}`);

    // B. Benchmark Bounded Min-Heap Top-K (O(N log K))
    const heapTimes = [];
    for (let w = 0; w < 5; w++) RiskPriorityQueue.topK(entries, K); // Warmup
    for (let iter = 0; iter < 20; iter++) {
      const t0 = performance.now();
      RiskPriorityQueue.topK(entries, K);
      const t1 = performance.now();
      heapTimes.push(t1 - t0);
    }
    const heapStats = stats(heapTimes);

    // C. Benchmark Full Array Sort (O(N log N))
    const sortTimes = [];
    for (let w = 0; w < 5; w++) {
      [...entries].sort((a, b) => b.priority - a.priority).slice(0, K);
    }
    for (let iter = 0; iter < 20; iter++) {
      const t0 = performance.now();
      const sorted = [...entries].sort((a, b) => b.priority - a.priority).slice(0, K);
      const t1 = performance.now();
      sortTimes.push(t1 - t0);
    }
    const sortStats = stats(sortTimes);

    const speedup = (sortStats.median / heapStats.median).toFixed(2);

    console.log(`  Heap Top-K (O(N log K)):   Median: ${formatDuration(heapStats.median)} | P95: ${formatDuration(heapStats.p95)}`);
    console.log(`  Full Array Sort (O(N log N)): Median: ${formatDuration(sortStats.median)} | P95: ${formatDuration(sortStats.p95)}`);
    console.log(`  Heap Advantage:             ${speedup}x faster than full sorting`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('QUALIFICATIONS & METHODOLOGY NOTES:');
  console.log('1. Scope: In-memory evaluation of mathematical scoring formula and binary heap');
  console.log('   priority queue Top-K selection algorithm.');
  console.log('2. Asymptotic Advantage: As N scales (e.g. 50,000 incidents), O(N log 20) performs');
  console.log('   ~215,000 heap operations vs ~780,000 array comparisons in O(N log N) Quicksort.');
  console.log('3. Exclusions: Does NOT include PostgreSQL disk I/O, network RTT, or HTTP parsing.');
  console.log('='.repeat(80));
}

runBenchmark();
