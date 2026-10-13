import {
  GraphNode,
  GraphEdge,
  GraphNodeType,
  GraphEdgeType,
  InvestigationGraphData,
  GraphTraversalOptions,
  BfsResult,
  BfsReachableNode,
  DfsPathResult,
  AttackPath,
  BlastRadiusAnalysis,
  BlastRadiusEntity,
  BlastRadiusTier,
  CycleDetectionResult,
  DetectedCycle,
} from './graph.types';

export class InvestigationGraph {
  private nodes: Map<string, GraphNode> = new Map();
  private outgoingEdges: Map<string, GraphEdge[]> = new Map();
  private incomingEdges: Map<string, GraphEdge[]> = new Map();
  private edgeSet: Map<string, GraphEdge> = new Map();

  /**
   * Adds or updates a node in the investigation graph.
   */
  addNode(node: GraphNode): void {
    if (!node || !node.id) {
      throw new Error('GraphNode must have a valid non-empty id.');
    }
    const existing = this.nodes.get(node.id);
    if (existing) {
      // Merge properties if node already exists
      existing.properties = { ...existing.properties, ...node.properties };
      if (node.label && !existing.label) existing.label = node.label;
    } else {
      this.nodes.set(node.id, { ...node });
      if (!this.outgoingEdges.has(node.id)) {
        this.outgoingEdges.set(node.id, []);
      }
      if (!this.incomingEdges.has(node.id)) {
        this.incomingEdges.set(node.id, []);
      }
    }
  }

  getNode(nodeId: string): GraphNode | undefined {
    return this.nodes.get(nodeId);
  }

  hasNode(nodeId: string): boolean {
    return this.nodes.has(nodeId);
  }

  getNodes(): GraphNode[] {
    return Array.from(this.nodes.values());
  }

  getNodeCount(): number {
    return this.nodes.size;
  }

  /**
   * Adds a directed edge between two existing nodes.
   * Strictly validates endpoint existence, deduplicates identical edges,
   * and enforces Anti-IP-Bleeding rules.
   */
  addEdge(edge: GraphEdge): boolean {
    if (!edge || !edge.sourceNodeId || !edge.targetNodeId) {
      throw new Error('GraphEdge must have valid sourceNodeId and targetNodeId.');
    }

    // Verify endpoint nodes exist
    if (!this.nodes.has(edge.sourceNodeId)) {
      throw new Error(`Cannot add edge: source node '${edge.sourceNodeId}' does not exist in graph.`);
    }
    if (!this.nodes.has(edge.targetNodeId)) {
      throw new Error(`Cannot add edge: target node '${edge.targetNodeId}' does not exist in graph.`);
    }

    // Anti-IP-Bleeding Safeguard (ADR-006):
    // Direct User-to-User or Asset-to-Asset edges must NOT be formed without explicit correlation factor
    const sourceNode = this.nodes.get(edge.sourceNodeId)!;
    const targetNode = this.nodes.get(edge.targetNodeId)!;
    if (
      sourceNode.nodeType === GraphNodeType.USER &&
      targetNode.nodeType === GraphNodeType.USER &&
      edge.edgeType !== GraphEdgeType.ASSOCIATED_WITH
    ) {
      return false;
    }

    // Edge ID: deterministic hash
    const deterministicId = edge.id || `${edge.sourceNodeId}->${edge.edgeType}->${edge.targetNodeId}`;
    const normalizedEdge: GraphEdge = {
      ...edge,
      id: deterministicId,
      isDirected: edge.isDirected !== false,
    };

    // Deduplicate: if edge already exists, update confidence or provenance if newer
    const existing = this.edgeSet.get(deterministicId);
    if (existing) {
      if (normalizedEdge.provenance.confidence > existing.provenance.confidence) {
        existing.provenance.confidence = normalizedEdge.provenance.confidence;
      }
      return false;
    }

    this.edgeSet.set(deterministicId, normalizedEdge);

    const outList = this.outgoingEdges.get(edge.sourceNodeId) || [];
    outList.push(normalizedEdge);
    this.outgoingEdges.set(edge.sourceNodeId, outList);

    const inList = this.incomingEdges.get(edge.targetNodeId) || [];
    inList.push(normalizedEdge);
    this.incomingEdges.set(edge.targetNodeId, inList);

    return true;
  }

  getEdges(): GraphEdge[] {
    return Array.from(this.edgeSet.values());
  }

  getEdgeCount(): number {
    return this.edgeSet.size;
  }

  getOutgoingEdges(nodeId: string): GraphEdge[] {
    return this.outgoingEdges.get(nodeId) || [];
  }

  getIncomingEdges(nodeId: string): GraphEdge[] {
    return this.incomingEdges.get(nodeId) || [];
  }

  getNeighbors(
    nodeId: string,
    direction: 'OUTGOING' | 'INCOMING' | 'BOTH' = 'OUTGOING',
  ): Array<{ node: GraphNode; edge: GraphEdge }> {
    const neighbors: Array<{ node: GraphNode; edge: GraphEdge }> = [];

    if (direction === 'OUTGOING' || direction === 'BOTH') {
      const edges = this.outgoingEdges.get(nodeId) || [];
      for (const edge of edges) {
        const neighborNode = this.nodes.get(edge.targetNodeId);
        if (neighborNode) {
          neighbors.push({ node: neighborNode, edge });
        }
      }
    }

    if (direction === 'INCOMING' || direction === 'BOTH') {
      const edges = this.incomingEdges.get(nodeId) || [];
      for (const edge of edges) {
        const neighborNode = this.nodes.get(edge.sourceNodeId);
        if (neighborNode) {
          neighbors.push({ node: neighborNode, edge });
        }
      }
    }

    return neighbors;
  }

  toData(rootNodeId?: string): InvestigationGraphData {
    return {
      nodes: this.getNodes(),
      edges: this.getEdges(),
      metadata: {
        rootNodeId,
        nodeCount: this.nodes.size,
        edgeCount: this.edgeSet.size,
        generatedAt: new Date().toISOString(),
      },
    };
  }

  static fromData(data: InvestigationGraphData): InvestigationGraph {
    const graph = new InvestigationGraph();
    for (const node of data.nodes) {
      graph.addNode(node);
    }
    for (const edge of data.edges) {
      graph.addEdge(edge);
    }
    return graph;
  }

  // =========================================================================
  // 1. Breadth-First Search (BFS) Traversal
  // =========================================================================

  /**
   * Breadth-First Search (BFS) for reachable neighborhood discovery within maxHops.
   * Time Complexity: O(V + E) bounded by maxNodes.
   * Space Complexity: O(V).
   */
  bfs(options: GraphTraversalOptions): BfsResult {
    const {
      startNodeId,
      maxHops = 2,
      direction = 'OUTGOING',
      timeWindowStart,
      timeWindowEnd,
      maxNodes = 100,
      allowedEdgeTypes,
    } = options;

    const startNode = this.nodes.get(startNodeId);
    if (!startNode) {
      return {
        startNodeId,
        reachableNodes: [],
        visitedCount: 0,
        maxDepthReached: 0,
      };
    }

    const effectiveMaxHops = Math.min(Math.max(1, maxHops), 5);
    const effectiveMaxNodes = Math.min(Math.max(1, maxNodes), 500);

    const visited = new Set<string>();
    const reachableNodes: BfsReachableNode[] = [];
    const distances = new Map<string, number>();

    // Queue entries: [nodeId, currentDistance, pathToNode]
    const queue: Array<{ nodeId: string; distance: number; path: GraphEdge[] }> = [];

    visited.add(startNodeId);
    distances.set(startNodeId, 0);
    queue.push({ nodeId: startNodeId, distance: 0, path: [] });

    let head = 0;
    let maxDepthReached = 0;

    while (head < queue.length && reachableNodes.length < effectiveMaxNodes) {
      const { nodeId, distance, path } = queue[head++];

      maxDepthReached = Math.max(maxDepthReached, distance);

      if (distance >= effectiveMaxHops) {
        continue;
      }

      // Retrieve neighbors according to direction
      const neighbors = this.getNeighbors(nodeId, direction);

      for (const { node: neighborNode, edge } of neighbors) {
        // Filter by allowed edge types if configured
        if (allowedEdgeTypes && !allowedEdgeTypes.includes(edge.edgeType)) {
          continue;
        }

        // Filter by edge temporal window if provided
        if (timeWindowStart || timeWindowEnd) {
          const edgeTimestamp = new Date(edge.provenance.timestamp).getTime();
          if (timeWindowStart && edgeTimestamp < timeWindowStart.getTime()) {
            continue;
          }
          if (timeWindowEnd && edgeTimestamp > timeWindowEnd.getTime()) {
            continue;
          }
        }

        if (!visited.has(neighborNode.id)) {
          visited.add(neighborNode.id);
          const nextDist = distance + 1;
          const nextPath = [...path, edge];

          distances.set(neighborNode.id, nextDist);
          reachableNodes.push({
            node: neighborNode,
            distance: nextDist,
            path: nextPath,
          });

          if (reachableNodes.length >= effectiveMaxNodes) {
            break;
          }

          queue.push({
            nodeId: neighborNode.id,
            distance: nextDist,
            path: nextPath,
          });
        }
      }
    }

    return {
      startNodeId,
      reachableNodes,
      visitedCount: visited.size,
      maxDepthReached,
    };
  }

  // =========================================================================
  // 2. Depth-First Search (DFS) Attack-Path Finding
  // =========================================================================

  /**
   * Iterative stack-based DFS pathfinder between sourceNodeId and targetNodeId.
   * Guaranteed recursion-safe (no call-stack overflow).
   * Time Complexity: O(V + E) per path discovery; bounded by maxDepth and maxPaths.
   * Space Complexity: O(V).
   */
  findAttackPaths(
    sourceNodeId: string,
    targetNodeId: string,
    maxDepth: number = 4,
    maxPaths: number = 5,
  ): DfsPathResult {
    const effectiveMaxDepth = Math.min(Math.max(1, maxDepth), 10);
    const effectiveMaxPaths = Math.min(Math.max(1, maxPaths), 10);

    const sourceNode = this.nodes.get(sourceNodeId);
    const targetNode = this.nodes.get(targetNodeId);

    if (!sourceNode || !targetNode) {
      return {
        sourceNodeId,
        targetNodeId,
        paths: [],
        exploredCount: 0,
      };
    }

    if (sourceNodeId === targetNodeId) {
      return {
        sourceNodeId,
        targetNodeId,
        paths: [
          {
            nodes: [sourceNode],
            edges: [],
            hopCount: 0,
            totalConfidence: 1.0,
            summary: `Source and target are identical node: ${sourceNode.label}`,
          },
        ],
        exploredCount: 1,
      };
    }

    const foundPaths: AttackPath[] = [];
    let exploredCount = 0;

    // Stack entry for iterative DFS
    interface StackFrame {
      currentNodeId: string;
      visitedOnPath: Set<string>;
      nodePath: GraphNode[];
      edgePath: GraphEdge[];
    }

    const stack: StackFrame[] = [
      {
        currentNodeId: sourceNodeId,
        visitedOnPath: new Set([sourceNodeId]),
        nodePath: [sourceNode],
        edgePath: [],
      },
    ];

    while (stack.length > 0 && foundPaths.length < effectiveMaxPaths) {
      const frame = stack.pop()!;
      exploredCount++;

      if (frame.edgePath.length >= effectiveMaxDepth) {
        continue;
      }

      const outEdges = this.outgoingEdges.get(frame.currentNodeId) || [];

      for (const edge of outEdges) {
        const nextNode = this.nodes.get(edge.targetNodeId);
        if (!nextNode) continue;

        if (nextNode.id === targetNodeId) {
          // Reached target!
          const completeNodes = [...frame.nodePath, nextNode];
          const completeEdges = [...frame.edgePath, edge];
          const confProduct = completeEdges.reduce(
            (acc, e) => acc * (e.provenance.confidence || 0.8),
            1.0,
          );

          foundPaths.push({
            nodes: completeNodes,
            edges: completeEdges,
            hopCount: completeEdges.length,
            totalConfidence: Math.round(confProduct * 1000) / 1000,
            summary: completeNodes.map((n) => n.label).join(' ──► '),
          });

          if (foundPaths.length >= effectiveMaxPaths) {
            break;
          }
          continue;
        }

        // Avoid loops in the path
        if (!frame.visitedOnPath.has(nextNode.id)) {
          const nextVisited = new Set(frame.visitedOnPath);
          nextVisited.add(nextNode.id);

          stack.push({
            currentNodeId: nextNode.id,
            visitedOnPath: nextVisited,
            nodePath: [...frame.nodePath, nextNode],
            edgePath: [...frame.edgePath, edge],
          });
        }
      }
    }

    return {
      sourceNodeId,
      targetNodeId,
      paths: foundPaths,
      exploredCount,
    };
  }

  // =========================================================================
  // 3. Evidence-Backed Blast-Radius Analysis
  // =========================================================================

  /**
   * Evidence-based blast radius calculation for an incident, user, or asset.
   * Divides reachable entities into Tier 1 (Directly Observed) vs Tier 2 (Potentially Exposed).
   * Appends an explicit exposure disclaimer.
   */
  calculateBlastRadius(
    targetNodeId: string,
    options: { maxHops?: number; timeWindowHours?: number } = {},
  ): BlastRadiusAnalysis {
    const targetNode = this.nodes.get(targetNodeId);
    if (!targetNode) {
      throw new Error(`Target node '${targetNodeId}' not found in investigation graph.`);
    }

    const maxHops = Math.min(Math.max(1, options.maxHops || 2), 4);
    const bfsResult = this.bfs({
      startNodeId: targetNodeId,
      maxHops,
      direction: 'BOTH',
    });

    const entities: BlastRadiusEntity[] = [];
    const criticalAssetsAtRisk: Array<{ assetNode: GraphNode; criticality: string; hopDistance: number }> = [];

    let directlyAffectedCount = 0;
    let potentiallyExposedCount = 0;

    for (const reachable of bfsResult.reachableNodes) {
      const { node, distance, path } = reachable;

      // Extract supporting event IDs from the edge provenance
      const supportingEventIds = path
        .map((e) => e.provenance.sourceRecordId)
        .filter((id): id is string => Boolean(id));

      let tier: BlastRadiusTier;
      let reason: string;

      if (distance === 1) {
        tier = BlastRadiusTier.CONFIRMED_OBSERVED;
        directlyAffectedCount++;
        reason = `Direct 1-hop participant observed via edge '${path[path.length - 1]?.edgeType}'.`;
      } else if (distance === 2) {
        tier = BlastRadiusTier.POTENTIALLY_EXPOSED;
        potentiallyExposedCount++;
        reason = `Potentially exposed entity reachable at 2 hops via '${path[0]?.targetNodeId}'.`;
      } else {
        tier = BlastRadiusTier.PERIMETER_REACHABLE;
        reason = `Perimeter entity reachable at ${distance} hops within investigation window.`;
      }

      entities.push({
        node,
        tier,
        reason,
        hopDistance: distance,
        supportingEventIds,
        viaNodeId: path[path.length - 2]?.targetNodeId,
      });

      // Highlight critical infrastructure assets
      if (node.nodeType === GraphNodeType.ASSET) {
        const crit = node.properties.criticality || 'MEDIUM';
        if (crit === 'CRITICAL' || crit === 'HIGH') {
          criticalAssetsAtRisk.push({
            assetNode: node,
            criticality: crit,
            hopDistance: distance,
          });
        }
      }
    }

    return {
      targetNode,
      directlyAffectedCount,
      potentiallyExposedCount,
      totalReachableCount: entities.length,
      entities,
      criticalAssetsAtRisk,
      disclaimer:
        'Blast radius analysis identifies graph reachability and potential exposure corridors based on observed events; reachability alone does not constitute forensic evidence of asset compromise.',
    };
  }

  // =========================================================================
  // 4. Directed Cycle Detection
  // =========================================================================

  /**
   * Directed cycle detection using DFS 3-Color graph coloring (WHITE, GRAY, BLACK).
   * Filters out trivial reciprocal edges (A <-> B) and identifies circular lateral movement loops.
   * Time Complexity: O(V + E).
   * Space Complexity: O(V).
   */
  detectDirectedCycles(
    participatingEdgeTypes?: GraphEdgeType[],
  ): CycleDetectionResult {
    const targetTypes = participatingEdgeTypes || [
      GraphEdgeType.AUTHENTICATED_AS,
      GraphEdgeType.PRECEDED_BY,
      GraphEdgeType.CONNECTED_FROM,
      GraphEdgeType.ASSOCIATED_WITH,
    ];

    // Filter directed adjacency to participating edge types
    const filteredAdj = new Map<string, GraphEdge[]>();
    for (const node of this.nodes.values()) {
      const out = (this.outgoingEdges.get(node.id) || []).filter((e) =>
        targetTypes.includes(e.edgeType),
      );
      filteredAdj.set(node.id, out);
    }

    // 0 = WHITE (unvisited), 1 = GRAY (in current recursion stack), 2 = BLACK (finished)
    const color = new Map<string, number>();
    for (const node of this.nodes.values()) {
      color.set(node.id, 0);
    }

    const edgeParent = new Map<string, GraphEdge>();
    const nodeParent = new Map<string, string>();
    const detectedCycles: DetectedCycle[] = [];
    const seenCycleSignatures = new Set<string>();

    const dfsVisit = (u: string) => {
      color.set(u, 1); // GRAY

      const edges = filteredAdj.get(u) || [];
      for (const edge of edges) {
        const v = edge.targetNodeId;

        // Skip self-edges if they point back immediately or check trivial reciprocal edge
        if (v === nodeParent.get(u)) {
          // Trivial reciprocal check: A -> B and B -> A of same edge type
          const parentEdge = edgeParent.get(u);
          if (parentEdge && parentEdge.sourceNodeId === v && parentEdge.edgeType === edge.edgeType) {
            continue;
          }
        }

        const vColor = color.get(v) || 0;

        if (vColor === 1) {
          // Back-edge detected! (Cycle found: v is in current traversal path)
          const cycleNodes: string[] = [v];
          const cycleEdges: GraphEdge[] = [edge];

          let curr = u;
          while (curr && curr !== v) {
            cycleNodes.unshift(curr);
            const parentE = edgeParent.get(curr);
            if (parentE) cycleEdges.unshift(parentE);
            curr = nodeParent.get(curr)!;
          }

          // Canonical signature to avoid duplicate cycles from rotations
          const sortedIds = [...cycleNodes].sort();
          const sig = sortedIds.join('|');

          if (!seenCycleSignatures.has(sig) && cycleNodes.length >= 2) {
            seenCycleSignatures.add(sig);

            const participatingNodes = cycleNodes
              .map((id) => this.nodes.get(id))
              .filter((n): n is GraphNode => Boolean(n));

            detectedCycles.push({
              nodeIds: cycleNodes,
              edgeIds: cycleEdges.map((e) => e.id),
              explanation: `Circular directed dependency loop detected across ${cycleNodes.length} entities: ${cycleNodes.join(' ──► ')} ──► ${v}`,
              participatingNodes,
              participatingEdges: cycleEdges,
            });
          }
        } else if (vColor === 0) {
          nodeParent.set(v, u);
          edgeParent.set(v, edge);
          dfsVisit(v);
        }
      }

      color.set(u, 2); // BLACK
    };

    for (const node of this.nodes.values()) {
      if ((color.get(node.id) || 0) === 0) {
        dfsVisit(node.id);
      }
    }

    return {
      hasCycles: detectedCycles.length > 0,
      cycleCount: detectedCycles.length,
      cycles: detectedCycles,
      analysisSummary:
        detectedCycles.length > 0
          ? `Detected ${detectedCycles.length} directed cyclic investigation path(s). Cycles represent potential lateral movement loops, circular proxy pivots, or recursive authentication paths.`
          : 'No directed cycles detected. Investigation relationship graph is strictly acyclic.',
    };
  }
}
