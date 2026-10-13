import { InvestigationGraph } from '../src/investigations/graph/investigation.graph';
import {
  GraphNodeType,
  GraphEdgeType,
  BlastRadiusTier,
} from '../src/investigations/graph/graph.types';

describe('Milestone 2.3: InvestigationGraph Data Model & Algorithmic Core', () => {
  let graph: InvestigationGraph;

  beforeEach(() => {
    graph = new InvestigationGraph();
  });

  describe('1. Node & Edge Data Model Validation', () => {
    it('should add valid nodes and reject nodes without id', () => {
      graph.addNode({
        id: 'user:alice',
        nodeType: GraphNodeType.USER,
        label: 'Alice (Security Admin)',
        properties: { email: 'alice@sentinelx.local' },
      });

      expect(graph.hasNode('user:alice')).toBe(true);
      expect(graph.getNode('user:alice')?.label).toBe('Alice (Security Admin)');
      expect(graph.getNodeCount()).toBe(1);

      expect(() => graph.addNode({} as any)).toThrow('GraphNode must have a valid non-empty id.');
    });

    it('should add valid edges and reject edges with non-existent endpoints', () => {
      graph.addNode({
        id: 'ip:198.51.100.22',
        nodeType: GraphNodeType.IP_ADDRESS,
        label: '198.51.100.22',
        properties: {},
      });
      graph.addNode({
        id: 'user:alice',
        nodeType: GraphNodeType.USER,
        label: 'Alice',
        properties: {},
      });

      const added = graph.addEdge({
        id: 'ip:198.51.100.22->AUTHENTICATED_AS->user:alice',
        sourceNodeId: 'ip:198.51.100.22',
        targetNodeId: 'user:alice',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Authenticated As',
        isDirected: true,
        provenance: {
          recordType: 'SECURITY_EVENT',
          timestamp: new Date().toISOString(),
          confidence: 1.0,
        },
      });

      expect(added).toBe(true);
      expect(graph.getEdgeCount()).toBe(1);

      // Non-existent target node
      expect(() =>
        graph.addEdge({
          id: 'test-invalid',
          sourceNodeId: 'user:alice',
          targetNodeId: 'user:nonexistent',
          edgeType: GraphEdgeType.ASSOCIATED_WITH,
          label: 'Invalid',
          isDirected: true,
          provenance: { recordType: 'TEST', timestamp: new Date().toISOString(), confidence: 1.0 },
        }),
      ).toThrow("target node 'user:nonexistent' does not exist");
    });

    it('should enforce Anti-IP-Bleeding: direct user-to-user edges rejected without explicit correlation factor', () => {
      graph.addNode({ id: 'user:alice', nodeType: GraphNodeType.USER, label: 'Alice', properties: {} });
      graph.addNode({ id: 'user:bob', nodeType: GraphNodeType.USER, label: 'Bob', properties: {} });

      const directEdgeResult = graph.addEdge({
        id: 'alice->AUTHENTICATED_AS->bob',
        sourceNodeId: 'user:alice',
        targetNodeId: 'user:bob',
        edgeType: GraphEdgeType.AUTHENTICATED_AS, // Invalid for user-user
        label: 'Direct link',
        isDirected: true,
        provenance: { recordType: 'TEST', timestamp: new Date().toISOString(), confidence: 1.0 },
      });

      expect(directEdgeResult).toBe(false);
      expect(graph.getEdgeCount()).toBe(0);
    });

    it('should deduplicate duplicate edges while preserving highest confidence', () => {
      graph.addNode({ id: 'ip:10.0.0.1', nodeType: GraphNodeType.IP_ADDRESS, label: '10.0.0.1', properties: {} });
      graph.addNode({ id: 'user:root', nodeType: GraphNodeType.USER, label: 'root', properties: {} });

      const e1 = graph.addEdge({
        id: 'ip:10.0.0.1->AUTHENTICATED_AS->user:root',
        sourceNodeId: 'ip:10.0.0.1',
        targetNodeId: 'user:root',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'SECURITY_EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 0.6 },
      });
      expect(e1).toBe(true);

      const e2 = graph.addEdge({
        id: 'ip:10.0.0.1->AUTHENTICATED_AS->user:root',
        sourceNodeId: 'ip:10.0.0.1',
        targetNodeId: 'user:root',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'SECURITY_EVENT', timestamp: '2026-10-13T10:05:00Z', confidence: 0.95 },
      });
      expect(e2).toBe(false); // Deduplicated!
      expect(graph.getEdgeCount()).toBe(1);
      expect(graph.getEdges()[0].provenance.confidence).toBe(0.95);
    });
  });

  describe('2. BFS Graph Traversal & Reachability', () => {
    beforeEach(() => {
      // Build a chain: N0 (IP) -> N1 (User) -> N2 (Asset) -> N3 (Asset) -> N4 (Incident)
      graph.addNode({ id: 'ip:1', nodeType: GraphNodeType.IP_ADDRESS, label: 'Attacker IP', properties: {} });
      graph.addNode({ id: 'user:1', nodeType: GraphNodeType.USER, label: 'Compromised User', properties: {} });
      graph.addNode({ id: 'asset:1', nodeType: GraphNodeType.ASSET, label: 'Bastion Host', properties: {} });
      graph.addNode({ id: 'asset:2', nodeType: GraphNodeType.ASSET, label: 'DB Server', properties: { criticality: 'CRITICAL' } });
      graph.addNode({ id: 'incident:1', nodeType: GraphNodeType.INCIDENT, label: 'INC-001', properties: {} });

      graph.addEdge({
        id: 'e1',
        sourceNodeId: 'ip:1',
        targetNodeId: 'user:1',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T12:00:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: 'e2',
        sourceNodeId: 'user:1',
        targetNodeId: 'asset:1',
        edgeType: GraphEdgeType.TARGETED_ASSET,
        label: 'Accessed',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T12:05:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: 'e3',
        sourceNodeId: 'asset:1',
        targetNodeId: 'asset:2',
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Connected',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T12:10:00Z', confidence: 0.9 },
      });
      graph.addEdge({
        id: 'e4',
        sourceNodeId: 'asset:2',
        targetNodeId: 'incident:1',
        edgeType: GraphEdgeType.PART_OF_INCIDENT,
        label: 'Part Of',
        isDirected: true,
        provenance: { recordType: 'INCIDENT', timestamp: '2026-10-13T12:15:00Z', confidence: 1.0 },
      });
    });

    it('should find 1-hop and 2-hop neighbors with correct distances', () => {
      const bfs1 = graph.bfs({ startNodeId: 'ip:1', maxHops: 1 });
      expect(bfs1.reachableNodes.length).toBe(1);
      expect(bfs1.reachableNodes[0].node.id).toBe('user:1');
      expect(bfs1.reachableNodes[0].distance).toBe(1);

      const bfs2 = graph.bfs({ startNodeId: 'ip:1', maxHops: 2 });
      expect(bfs2.reachableNodes.length).toBe(2);
      expect(bfs2.reachableNodes.map((n) => n.node.id)).toEqual(['user:1', 'asset:1']);
      expect(bfs2.maxDepthReached).toBe(2);
    });

    it('should cap traversal at maxHops ceiling', () => {
      const bfsFull = graph.bfs({ startNodeId: 'ip:1', maxHops: 4 });
      expect(bfsFull.reachableNodes.length).toBe(4);
      expect(bfsFull.maxDepthReached).toBe(4);
      expect(bfsFull.reachableNodes.map((n) => n.node.id)).toContain('incident:1');
    });

    it('should gracefully handle non-existent start node or disconnected node', () => {
      const emptyRes = graph.bfs({ startNodeId: 'nonexistent:id' });
      expect(emptyRes.reachableNodes).toEqual([]);
      expect(emptyRes.visitedCount).toBe(0);

      graph.addNode({ id: 'isolated:node', nodeType: GraphNodeType.ASSET, label: 'Isolated', properties: {} });
      const isolatedRes = graph.bfs({ startNodeId: 'isolated:node', maxHops: 3 });
      expect(isolatedRes.reachableNodes).toEqual([]);
      expect(isolatedRes.visitedCount).toBe(1);
    });
  });

  describe('3. DFS Attack Path Discovery', () => {
    beforeEach(() => {
      // Create a diamond graph:
      //         S
      //       /   \
      //      A     B
      //       \   /
      //         T
      graph.addNode({ id: 'S', nodeType: GraphNodeType.IP_ADDRESS, label: 'Source IP', properties: {} });
      graph.addNode({ id: 'A', nodeType: GraphNodeType.USER, label: 'User Alice', properties: {} });
      graph.addNode({ id: 'B', nodeType: GraphNodeType.USER, label: 'User Bob', properties: {} });
      graph.addNode({ id: 'T', nodeType: GraphNodeType.ASSET, label: 'Target Crown Jewel', properties: {} });

      graph.addEdge({
        id: 'S->A',
        sourceNodeId: 'S',
        targetNodeId: 'A',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 0.9 },
      });
      graph.addEdge({
        id: 'S->B',
        sourceNodeId: 'S',
        targetNodeId: 'B',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 0.8 },
      });
      graph.addEdge({
        id: 'A->T',
        sourceNodeId: 'A',
        targetNodeId: 'T',
        edgeType: GraphEdgeType.TARGETED_ASSET,
        label: 'Access',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:10:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: 'B->T',
        sourceNodeId: 'B',
        targetNodeId: 'T',
        edgeType: GraphEdgeType.TARGETED_ASSET,
        label: 'Access',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:10:00Z', confidence: 0.9 },
      });
    });

    it('should find both distinct attack paths from S to T', () => {
      const res = graph.findAttackPaths('S', 'T', 4, 5);
      expect(res.paths.length).toBe(2);

      const pathSummaries = res.paths.map((p) => p.summary);
      expect(pathSummaries).toContain('Source IP ──► User Alice ──► Target Crown Jewel');
      expect(pathSummaries).toContain('Source IP ──► User Bob ──► Target Crown Jewel');
      expect(res.paths[0].hopCount).toBe(2);
    });

    it('should return empty if target is unreachable', () => {
      graph.addNode({ id: 'Unreachable', nodeType: GraphNodeType.ASSET, label: 'Isolated Asset', properties: {} });
      const res = graph.findAttackPaths('S', 'Unreachable', 4, 5);
      expect(res.paths.length).toBe(0);
    });
  });

  describe('4. Blast-Radius Analysis', () => {
    beforeEach(() => {
      graph.addNode({ id: 'incident:inc-1', nodeType: GraphNodeType.INCIDENT, label: 'INC-BruteForce', properties: {} });
      graph.addNode({ id: 'user:victim', nodeType: GraphNodeType.USER, label: 'Victim User', properties: {} });
      graph.addNode({
        id: 'asset:crit-db',
        nodeType: GraphNodeType.ASSET,
        label: 'Production DB',
        properties: { criticality: 'CRITICAL' },
      });
      graph.addNode({
        id: 'asset:dev-vm',
        nodeType: GraphNodeType.ASSET,
        label: 'Dev VM',
        properties: { criticality: 'LOW' },
      });

      // 1 hop from incident to victim
      graph.addEdge({
        id: 'e-inc-user',
        sourceNodeId: 'incident:inc-1',
        targetNodeId: 'user:victim',
        edgeType: GraphEdgeType.PART_OF_INCIDENT,
        label: 'Targeted User',
        isDirected: true,
        provenance: { sourceRecordId: 'evt-100', recordType: 'SECURITY_EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 1.0 },
      });

      // 2 hops from incident to assets
      graph.addEdge({
        id: 'e-user-db',
        sourceNodeId: 'user:victim',
        targetNodeId: 'asset:crit-db',
        edgeType: GraphEdgeType.TARGETED_ASSET,
        label: 'Granted DB Access',
        isDirected: true,
        provenance: { sourceRecordId: 'evt-101', recordType: 'SECURITY_EVENT', timestamp: '2026-10-13T10:05:00Z', confidence: 0.9 },
      });
      graph.addEdge({
        id: 'e-user-dev',
        sourceNodeId: 'user:victim',
        targetNodeId: 'asset:dev-vm',
        edgeType: GraphEdgeType.TARGETED_ASSET,
        label: 'Granted VM Access',
        isDirected: true,
        provenance: { sourceRecordId: 'evt-102', recordType: 'SECURITY_EVENT', timestamp: '2026-10-13T10:06:00Z', confidence: 0.8 },
      });
    });

    it('should classify Tier 1 directly observed vs Tier 2 potentially exposed', () => {
      const blast = graph.calculateBlastRadius('incident:inc-1', { maxHops: 2 });

      expect(blast.targetNode.id).toBe('incident:inc-1');
      expect(blast.directlyAffectedCount).toBe(1); // user:victim at distance 1
      expect(blast.potentiallyExposedCount).toBe(2); // asset:crit-db & asset:dev-vm at distance 2

      const tier1 = blast.entities.find((e) => e.node.id === 'user:victim');
      expect(tier1?.tier).toBe(BlastRadiusTier.CONFIRMED_OBSERVED);
      expect(tier1?.supportingEventIds).toContain('evt-100');

      const tier2 = blast.entities.find((e) => e.node.id === 'asset:crit-db');
      expect(tier2?.tier).toBe(BlastRadiusTier.POTENTIALLY_EXPOSED);

      // Verify critical asset at risk was identified
      expect(blast.criticalAssetsAtRisk.length).toBe(1);
      expect(blast.criticalAssetsAtRisk[0].assetNode.id).toBe('asset:crit-db');
      expect(blast.criticalAssetsAtRisk[0].criticality).toBe('CRITICAL');

      // Verify explicit disclaimer is returned
      expect(blast.disclaimer).toContain('reachability alone does not constitute forensic evidence');
    });
  });

  describe('5. Directed Cycle Detection', () => {
    it('should report no cycles on strictly directed acyclic graph (DAG)', () => {
      graph.addNode({ id: '1', nodeType: GraphNodeType.IP_ADDRESS, label: '1', properties: {} });
      graph.addNode({ id: '2', nodeType: GraphNodeType.USER, label: '2', properties: {} });
      graph.addNode({ id: '3', nodeType: GraphNodeType.ASSET, label: '3', properties: {} });

      graph.addEdge({
        id: '1->2',
        sourceNodeId: '1',
        targetNodeId: '2',
        edgeType: GraphEdgeType.AUTHENTICATED_AS,
        label: 'Auth',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: '2->3',
        sourceNodeId: '2',
        targetNodeId: '3',
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Assoc',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 1.0 },
      });

      const res = graph.detectDirectedCycles();
      expect(res.hasCycles).toBe(false);
      expect(res.cycleCount).toBe(0);
      expect(res.analysisSummary).toContain('strictly acyclic');
    });

    it('should detect lateral movement cycle (A -> B -> C -> A)', () => {
      graph.addNode({ id: 'H1', nodeType: GraphNodeType.ASSET, label: 'Host 1', properties: {} });
      graph.addNode({ id: 'H2', nodeType: GraphNodeType.ASSET, label: 'Host 2', properties: {} });
      graph.addNode({ id: 'H3', nodeType: GraphNodeType.ASSET, label: 'Host 3', properties: {} });

      graph.addEdge({
        id: 'H1->H2',
        sourceNodeId: 'H1',
        targetNodeId: 'H2',
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Pivot 1',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:00:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: 'H2->H3',
        sourceNodeId: 'H2',
        targetNodeId: 'H3',
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Pivot 2',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:01:00Z', confidence: 1.0 },
      });
      graph.addEdge({
        id: 'H3->H1',
        sourceNodeId: 'H3',
        targetNodeId: 'H1',
        edgeType: GraphEdgeType.ASSOCIATED_WITH,
        label: 'Pivot 3 (Back)',
        isDirected: true,
        provenance: { recordType: 'EVENT', timestamp: '2026-10-13T10:02:00Z', confidence: 1.0 },
      });

      const res = graph.detectDirectedCycles();
      expect(res.hasCycles).toBe(true);
      expect(res.cycleCount).toBe(1);
      expect(res.cycles[0].nodeIds.length).toBe(3);
      expect(res.cycles[0].explanation).toContain('Circular directed dependency loop detected');
    });
  });
});
