export enum GraphNodeType {
  INCIDENT = 'INCIDENT',
  SECURITY_EVENT = 'SECURITY_EVENT',
  DETECTION = 'DETECTION',
  USER = 'USER',
  IP_ADDRESS = 'IP_ADDRESS',
  ASSET = 'ASSET',
}

export enum GraphEdgeType {
  AUTHENTICATED_AS = 'AUTHENTICATED_AS',   // IP -> USER (Observed auth event)
  CONNECTED_FROM = 'CONNECTED_FROM',       // EVENT -> IP (Observed network source)
  TARGETED_USER = 'TARGETED_USER',         // EVENT -> USER (Target identity)
  TARGETED_ASSET = 'TARGETED_ASSET',       // EVENT -> ASSET (Target destination host)
  RESOLVES_TO = 'RESOLVES_TO',             // ASSET -> IP (Asset network interface binding)
  TRIGGERED = 'TRIGGERED',                 // EVENT -> DETECTION
  PART_OF_INCIDENT = 'PART_OF_INCIDENT',   // EVENT/DETECTION -> INCIDENT
  PRECEDED_BY = 'PRECEDED_BY',             // EVENT -> EVENT (Temporal kill-chain progression)
  ASSOCIATED_WITH = 'ASSOCIATED_WITH',     // Entity -> Entity (Corroborated by correlation factor)
}

export interface GraphNode {
  id: string;               // Deterministic URN: e.g. "incident:<uuid>", "user:alice", "ip:198.51.100.22", "asset:<uuid>"
  nodeType: GraphNodeType;
  label: string;            // Human-readable title
  properties: {
    entityId?: string;
    severity?: string;
    criticality?: string;
    environment?: string;
    isInternal?: boolean;
    firstSeen?: string;
    lastSeen?: string;
    eventCount?: number;
    metadata?: Record<string, any>;
    [key: string]: any;
  };
}

export interface GraphEdgeProvenance {
  sourceRecordId?: string;
  recordType: string;       // e.g. 'SECURITY_EVENT', 'DETECTION', 'ASSET_INVENTORY', 'CORRELATION_CLUSTER'
  timestamp: string;
  confidence: number;       // 1.0 for directly observed facts; 0.5-0.9 for inferred correlations
  evidenceDetails?: Record<string, any>;
}

export interface GraphEdge {
  id: string;               // Deterministic hash: `${sourceNodeId}->${edgeType}->${targetNodeId}`
  sourceNodeId: string;
  targetNodeId: string;
  edgeType: GraphEdgeType;
  label: string;
  isDirected: boolean;
  provenance: GraphEdgeProvenance;
}

export interface GraphMetadata {
  rootNodeId?: string;
  nodeCount: number;
  edgeCount: number;
  timeWindowStart?: string;
  timeWindowEnd?: string;
  generatedAt: string;
}

export interface InvestigationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: GraphMetadata;
}

export interface GraphTraversalOptions {
  startNodeId: string;
  maxHops?: number;         // Default: 2, Max: 5
  direction?: 'OUTGOING' | 'INCOMING' | 'BOTH';
  timeWindowStart?: Date;
  timeWindowEnd?: Date;
  maxNodes?: number;        // Default: 100, Max: 500
  allowedEdgeTypes?: GraphEdgeType[];
}

export interface BfsReachableNode {
  node: GraphNode;
  distance: number;
  path: GraphEdge[];
}

export interface BfsResult {
  startNodeId: string;
  reachableNodes: BfsReachableNode[];
  visitedCount: number;
  maxDepthReached: number;
}

export interface AttackPath {
  nodes: GraphNode[];
  edges: GraphEdge[];
  hopCount: number;
  totalConfidence: number;
  summary: string;
}

export interface DfsPathResult {
  sourceNodeId: string;
  targetNodeId: string;
  paths: AttackPath[];
  exploredCount: number;
}

export enum BlastRadiusTier {
  CONFIRMED_OBSERVED = 'CONFIRMED_OBSERVED',   // Tier 1: Directly observed in malicious event/detection
  POTENTIALLY_EXPOSED = 'POTENTIALLY_EXPOSED', // Tier 2: 1-2 hops via shared credential or reachable asset interface
  PERIMETER_REACHABLE = 'PERIMETER_REACHABLE', // Tier 3: 3+ hops reachable in neighborhood
}

export interface BlastRadiusEntity {
  node: GraphNode;
  tier: BlastRadiusTier;
  reason: string;
  hopDistance: number;
  supportingEventIds: string[];
  viaNodeId?: string;
}

export interface BlastRadiusAnalysis {
  targetNode: GraphNode;
  directlyAffectedCount: number;
  potentiallyExposedCount: number;
  totalReachableCount: number;
  entities: BlastRadiusEntity[];
  criticalAssetsAtRisk: Array<{ assetNode: GraphNode; criticality: string; hopDistance: number }>;
  disclaimer: string;
}

export interface DetectedCycle {
  nodeIds: string[];
  edgeIds: string[];
  explanation: string;
  participatingNodes: GraphNode[];
  participatingEdges: GraphEdge[];
}

export interface CycleDetectionResult {
  hasCycles: boolean;
  cycleCount: number;
  cycles: DetectedCycle[];
  analysisSummary: string;
}
