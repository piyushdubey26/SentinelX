#!/usr/bin/env node

/**
 * SentinelX Milestone 2.3 - Graph-Based Security Investigation Benchmark
 * 
 * Evaluates in-memory graph data structure performance:
 * - Graph construction (node/edge addition, deduplication, anti-IP-bleeding invariant check)
 * - Breadth-First Search (BFS) neighborhood traversal (O(V + E))
 * - Depth-First Search (DFS) multi-hop attack path discovery
 * - Blast Radius calculation (Tier 1 vs Tier 2 attribution)
 * - Directed Cycle Detection (DFS 3-color coloring)
 * 
 * Benchmarks across graph scales:
 * - Small:  N = 100 nodes  (~250 edges)
 * - Medium: N = 500 nodes  (~1,250 edges)
 * - Large:  N = 2,000 nodes (~5,000 edges)
 * 
 * Uses deterministic pseudo-random number generator (LCG) with warmups and multi-iteration metrics.
 */

const { InvestigationGraph } = require('../dist/investigations/graph/investigation.graph');
const {
  GraphNodeType,
  GraphEdgeType,
  BlastRadiusTier,
} = require('../dist/investigations/graph/graph.types');

/**
 * Deterministic Linear Congruential Generator (LCG) for reproducible benchmarks
 */
class DeterministicPRNG {
  constructor(seed = 4242) {
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
 * Generates synthetic security investigation graphs deterministically
 */
function generateSyntheticGraph(nodeCount, seed = 1337) {
  const prng = new DeterministicPRNG(seed);
  const graph = new InvestigationGraph();

  const ipCount = Math.max(2, Math.floor(nodeCount * 0.15));
  const userCount = Math.max(2, Math.floor(nodeCount * 0.15));
  const assetCount = Math.max(2, Math.floor(nodeCount * 0.15));
  const detectionCount = Math.max(2, Math.floor(nodeCount * 0.15));
  const eventCount = nodeCount - ipCount - userCount - assetCount - detectionCount;

  const ipNodes = [];
  const userNodes = [];
  const assetNodes = [];
  const detectionNodes = [];
  const eventNodes = [];

  const now = Date.now();

  // 1. Generate Nodes
  for (let i = 0; i < ipCount; i++) {
    const id = `ip:198.51.100.${(i % 250) + 1}`;
    graph.addNode({
      id,
      nodeType: GraphNodeType.IP_ADDRESS,
      label: `198.51.100.${(i % 250) + 1}`,
      properties: {
        isInternal: i % 3 === 0,
        firstSeen: new Date(now - 3600000).toISOString(),
        lastSeen: new Date(now).toISOString(),
      },
    });
    ipNodes.push(id);
  }

  for (let i = 0; i < userCount; i++) {
    const id = `user:analyst_user_${i}`;
    graph.addNode({
      id,
      nodeType: GraphNodeType.USER,
      label: `analyst_user_${i}`,
      properties: {
        department: 'SecOps',
        firstSeen: new Date(now - 3600000).toISOString(),
        lastSeen: new Date(now).toISOString(),
      },
    });
    userNodes.push(id);
  }

  for (let i = 0; i < assetCount; i++) {
    const id = `asset:srv-prod-${i}`;
    graph.addNode({
      id,
      nodeType: GraphNodeType.ASSET,
      label: `srv-prod-${i}.internal`,
      properties: {
        criticality: i % 5 === 0 ? 'CRITICAL' : 'HIGH',
        environment: 'production',
        firstSeen: new Date(now - 3600000).toISOString(),
        lastSeen: new Date(now).toISOString(),
      },
    });
    assetNodes.push(id);
  }

  for (let i = 0; i < detectionCount; i++) {
    const id = `detection:rule-${i}`;
    graph.addNode({
      id,
      nodeType: GraphNodeType.DETECTION,
      label: `DETECTION_RULE_${i}`,
      properties: {
        severity: i % 2 === 0 ? 'HIGH' : 'CRITICAL',
        firstSeen: new Date(now - 3600000).toISOString(),
      },
    });
    detectionNodes.push(id);
  }

  for (let i = 0; i < eventCount; i++) {
    const id = `event:evt-${i}`;
    graph.addNode({
      id,
      nodeType: GraphNodeType.SECURITY_EVENT,
      label: `AUTH_FAILURE_${i}`,
      properties: {
        severity: 'MEDIUM',
        firstSeen: new Date(now - 1800000 + i * 1000).toISOString(),
        lastSeen: new Date(now - 1800000 + i * 1000).toISOString(),
      },
    });
    eventNodes.push(id);
  }

  // 2. Generate Edges (IP -> EVENT -> ASSET / USER / DETECTION)
  let edgeIdCounter = 0;
  for (const eventId of eventNodes) {
    // Inbound from an IP (IP -> EVENT)
    const srcIp = prng.pick(ipNodes);
    graph.addEdge({
      id: `${srcIp}->CONNECTED_FROM->${eventId}`,
      sourceNodeId: srcIp,
      targetNodeId: eventId,
      edgeType: GraphEdgeType.CONNECTED_FROM,
      label: 'Connected From',
      isDirected: true,
      provenance: {
        recordType: 'SECURITY_EVENT',
        confidence: 1.0,
        timestamp: new Date(now - 100000).toISOString(),
      },
    });

    // Outbound to Asset (EVENT -> ASSET)
    const targetAsset = prng.pick(assetNodes);
    graph.addEdge({
      id: `${eventId}->TARGETED_ASSET->${targetAsset}`,
      sourceNodeId: eventId,
      targetNodeId: targetAsset,
      edgeType: GraphEdgeType.TARGETED_ASSET,
      label: 'Targeted Asset',
      isDirected: true,
      provenance: {
        recordType: 'SECURITY_EVENT',
        confidence: 1.0,
        timestamp: new Date(now - 90000).toISOString(),
      },
    });

    // Outbound to User (50% probability) (EVENT -> USER)
    if (prng.next() > 0.5) {
      const targetUser = prng.pick(userNodes);
      graph.addEdge({
        id: `${eventId}->AUTHENTICATED_AS->${targetUser}`,
        sourceNodeId: eventId,
        targetNodeId: targetUser,
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Authenticated As',
        isDirected: true,
        provenance: {
          recordType: 'SECURITY_EVENT',
          confidence: 1.0,
          timestamp: new Date(now - 80000).toISOString(),
        },
      });
    }

    // Triggered Detection (40% probability) (EVENT -> DETECTION)
    if (prng.next() > 0.6) {
      const det = prng.pick(detectionNodes);
      graph.addEdge({
        id: `${eventId}->TRIGGERED->${det}`,
        sourceNodeId: eventId,
        targetNodeId: det,
        edgeType: GraphEdgeType.TRIGGERED,
        label: 'Triggered Detection',
        isDirected: true,
        provenance: {
          recordType: 'DETECTION',
          confidence: 1.0,
          timestamp: new Date(now - 70000).toISOString(),
        },
      });
    }
  }

  // Preceded-by temporal links between consecutive events
  for (let e = 1; e < Math.min(eventNodes.length, 50); e++) {
    graph.addEdge({
      id: `${eventNodes[e - 1]}->PRECEDED_BY->${eventNodes[e]}`,
      sourceNodeId: eventNodes[e - 1],
      targetNodeId: eventNodes[e],
      edgeType: GraphEdgeType.PRECEDED_BY,
      label: 'Preceded By',
      isDirected: true,
      provenance: {
        recordType: 'CORRELATION_CLUSTER',
        confidence: 0.85,
        timestamp: new Date(now - 60000).toISOString(),
      },
    });
  }

  // Controlled directed cycles for cycle detection validation (EVENT -> DETECTION -> EVENT)
  const cycleCount = Math.max(1, Math.floor(nodeCount * 0.02));
  for (let c = 0; c < cycleCount; c++) {
    const e1 = prng.pick(eventNodes);
    const d1 = prng.pick(detectionNodes);
    const e2 = prng.pick(eventNodes);
    if (e1 !== e2) {
      graph.addEdge({
        id: `cycle_1_${c}`,
        sourceNodeId: e1,
        targetNodeId: d1,
        edgeType: GraphEdgeType.TRIGGERED,
        label: 'Triggered',
        isDirected: true,
        provenance: {
          recordType: 'DETECTION',
          confidence: 0.9,
          timestamp: new Date(now - 50000).toISOString(),
        },
      });
      graph.addEdge({
        id: `cycle_2_${c}`,
        sourceNodeId: d1,
        targetNodeId: e2,
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Associated With',
        isDirected: true,
        provenance: {
          recordType: 'CORRELATION_CLUSTER',
          confidence: 0.8,
          timestamp: new Date(now - 40000).toISOString(),
        },
      });
      graph.addEdge({
        id: `cycle_3_${c}`,
        sourceNodeId: e2,
        targetNodeId: e1,
        edgeType: GraphEdgeType.PRECEDED_BY,
        label: 'Preceded By',
        isDirected: true,
        provenance: {
          recordType: 'CORRELATION_CLUSTER',
          confidence: 0.8,
          timestamp: new Date(now - 30000).toISOString(),
        },
      });
    }
  }

  return { graph, ipNodes, userNodes, assetNodes, detectionNodes, eventNodes };
}

/**
 * Statistical calculations
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

function formatMs(ms) {
  return ms < 1 ? `${(ms * 1000).toFixed(1)} µs` : `${ms.toFixed(3)} ms`;
}

/**
 * Run Benchmark Suite
 */
function runBenchmarks() {
  console.log('='.repeat(80));
  console.log('SENTINELX MILESTONE 2.3: GRAPH ALGORITHM BENCHMARK SUITE');
  console.log('='.repeat(80));
  console.log(`Node.js Version: ${process.version}`);
  console.log(`OS: ${process.platform} ${process.arch}`);
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`Benchmark Scope: In-memory adjacency list, BFS, DFS path finding, blast radius, cycle detection`);
  console.log('-'.repeat(80));

  const scales = [
    { name: 'Small Graph', nodeCount: 100, iterations: 50, warmups: 10 },
    { name: 'Medium Graph', nodeCount: 500, iterations: 30, warmups: 5 },
    { name: 'Large Graph', nodeCount: 2000, iterations: 15, warmups: 3 },
  ];

  for (const scale of scales) {
    console.log(`\n>>> Evaluating ${scale.name} (N = ${scale.nodeCount} nodes)`);
    const initialMem = process.memoryUsage().heapUsed;

    // 1. Graph Construction Benchmark
    const constructTimes = [];
    let sampleData = null;

    for (let i = 0; i < scale.warmups + scale.iterations; i++) {
      const t0 = performance.now();
      const generated = generateSyntheticGraph(scale.nodeCount, 1000 + i);
      const t1 = performance.now();
      if (i >= scale.warmups) {
        constructTimes.push(t1 - t0);
      }
      if (i === scale.warmups + scale.iterations - 1) {
        sampleData = generated;
      }
    }

    const { graph, ipNodes, assetNodes } = sampleData;
    const finalMem = process.memoryUsage().heapUsed;
    const heapDeltaMb = ((finalMem - initialMem) / (1024 * 1024)).toFixed(2);

    console.log(`  Nodes count: ${graph.getNodeCount()}, Edges count: ${graph.getEdgeCount()}`);
    console.log(`  Approx memory delta: ${heapDeltaMb} MB`);

    const cStats = stats(constructTimes);
    console.log(`  [Construction]        Median: ${formatMs(cStats.median)} | P95: ${formatMs(cStats.p95)} | Min-Max: [${formatMs(cStats.min)}, ${formatMs(cStats.max)}]`);

    // 2. BFS Traversal Benchmark
    const bfsTimes = [];
    const rootNodes = [ipNodes[0], ipNodes[1], assetNodes[0]];

    // Warmup
    for (let i = 0; i < scale.warmups; i++) {
      graph.bfs(rootNodes[i % rootNodes.length], { maxHops: 3, maxNodes: 500 });
    }
    // Measured
    for (let i = 0; i < scale.iterations; i++) {
      const startNode = rootNodes[i % rootNodes.length];
      const t0 = performance.now();
      const result = graph.bfs(startNode, { maxHops: 3, maxNodes: 500 });
      const t1 = performance.now();
      bfsTimes.push(t1 - t0);
    }
    const bfsStats = stats(bfsTimes);
    const bfsOpsSec = (1000 / bfsStats.mean).toFixed(0);
    console.log(`  [BFS (maxHops=3)]      Median: ${formatMs(bfsStats.median)} | P95: ${formatMs(bfsStats.p95)} | Ops/sec: ${bfsOpsSec}`);

    // 3. DFS Attack Path Search Benchmark
    const dfsTimes = [];
    const srcNode = ipNodes[0];
    const tgtNode = assetNodes[0];

    // Warmup
    for (let i = 0; i < scale.warmups; i++) {
      graph.findAttackPaths(srcNode, tgtNode, { maxDepth: 4, maxPaths: 10 });
    }
    // Measured
    for (let i = 0; i < scale.iterations; i++) {
      const t0 = performance.now();
      const paths = graph.findAttackPaths(srcNode, tgtNode, { maxDepth: 4, maxPaths: 10 });
      const t1 = performance.now();
      dfsTimes.push(t1 - t0);
    }
    const dfsStats = stats(dfsTimes);
    const dfsOpsSec = (1000 / dfsStats.mean).toFixed(0);
    console.log(`  [DFS Pathfinding]     Median: ${formatMs(dfsStats.median)} | P95: ${formatMs(dfsStats.p95)} | Ops/sec: ${dfsOpsSec}`);

    // 4. Blast Radius Benchmark
    const blastTimes = [];
    const blastRoot = assetNodes[0];

    // Warmup
    for (let i = 0; i < scale.warmups; i++) {
      graph.calculateBlastRadius(blastRoot, { maxHops: 2 });
    }
    // Measured
    for (let i = 0; i < scale.iterations; i++) {
      const t0 = performance.now();
      const blast = graph.calculateBlastRadius(blastRoot, { maxHops: 2 });
      const t1 = performance.now();
      blastTimes.push(t1 - t0);
    }
    const blastStats = stats(blastTimes);
    const blastOpsSec = (1000 / blastStats.mean).toFixed(0);
    console.log(`  [Blast Radius (H=2)]  Median: ${formatMs(blastStats.median)} | P95: ${formatMs(blastStats.p95)} | Ops/sec: ${blastOpsSec}`);

    // 5. Cycle Detection Benchmark
    const cycleTimes = [];

    // Warmup
    for (let i = 0; i < scale.warmups; i++) {
      graph.detectDirectedCycles();
    }
    // Measured
    for (let i = 0; i < scale.iterations; i++) {
      const t0 = performance.now();
      const cycles = graph.detectDirectedCycles();
      const t1 = performance.now();
      cycleTimes.push(t1 - t0);
    }
    const cycleStats = stats(cycleTimes);
    const cycleOpsSec = (1000 / cycleStats.mean).toFixed(0);
    console.log(`  [Cycle Detection]     Median: ${formatMs(cycleStats.median)} | P95: ${formatMs(cycleStats.p95)} | Ops/sec: ${cycleOpsSec}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('QUALIFICATIONS & METHODOLOGY NOTES:');
  console.log('1. Workload Scope: Evaluates pure in-memory algorithmic latency of adjacency-list');
  console.log('   graph algorithms (BFS, iterative DFS, 3-color cycle detection, blast radius).');
  console.log('2. Exclusions: Does NOT include PostgreSQL query latency, ORM serialization overhead,');
  console.log('   or HTTP REST JSON serialization.');
  console.log('3. Anti-IP-Bleeding Check: Graph insertion strictly enforces anti-IP-bleeding invariant');
  console.log('   (rejects raw IP-IP or multi-tenant IP-asset links without correlation factor).');
  console.log('4. Safety Ceilings: Traversal strictly bound by maxHops <= 5 and maxDepth <= 6.');
  console.log('='.repeat(80));
}

runBenchmarks();
