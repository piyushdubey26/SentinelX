export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  permissions: string[];
}

export interface AuthResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  user: UserProfile;
}

export interface DetectionEvidence {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  sourceIp: string;
  targetUser?: string;
  triggerCount: number;
  timeWindowSeconds: number;
  evidence: {
    triggerEventIds?: string[];
    sourceKey?: string;
    timestamp?: string;
    [key: string]: any;
  };
  detectedAt: string;
}

export interface Incident {
  id: string;
  code: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  sourceIp?: string;
  detectionId?: string;
  detection?: DetectionEvidence;
  assignedTo?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
  };
  riskScore?: number;
  riskTier?: RiskTier;
  riskFactors?: RiskScoreBreakdown;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentMetrics {
  criticalCount: number;
  openCount: number;
  totalCount: number;
}

export interface BackendHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptimeSeconds: number;
  environment: string;
  database: {
    connected: boolean;
    databaseName: string;
  };
  version: string;
}

export interface CorrelationFactor {
  factorType: string;
  weight: number;
  contribution: number;
  description: string;
  evidence: Record<string, any>;
}

export interface CandidateIncident {
  id: string;
  title: string;
  summary: string;
  confidenceScore: number;
  severity: Severity;
  status: 'CANDIDATE' | 'PROMOTED' | 'DISMISSED';
  correlationFactors: CorrelationFactor[];
  explanation: string;
  primaryUser?: string;
  primarySourceIp?: string;
  primaryAssetId?: string;
  eventIds: string[];
  detectionIds: string[];
  incidentId?: string;
  dismissedReason?: string;
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
  updatedAt: string;
}

// ==========================================
// Milestone 2.3 Graph Investigation Types
// ==========================================

export type GraphNodeType =
  | 'INCIDENT'
  | 'SECURITY_EVENT'
  | 'DETECTION'
  | 'USER'
  | 'IP_ADDRESS'
  | 'ASSET';

export type GraphEdgeType =
  | 'AUTHENTICATED_AS'
  | 'CONNECTED_FROM'
  | 'TARGETED_USER'
  | 'TARGETED_ASSET'
  | 'RESOLVES_TO'
  | 'TRIGGERED'
  | 'PART_OF_INCIDENT'
  | 'PRECEDED_BY'
  | 'ASSOCIATED_WITH';

export interface GraphNode {
  id: string;
  nodeType: GraphNodeType;
  label: string;
  properties: {
    entityId?: string;
    severity?: string;
    criticality?: string;
    environment?: string;
    isInternal?: boolean;
    firstSeen?: string;
    lastSeen?: string;
    eventCount?: number;
    [key: string]: any;
  };
}

export interface GraphEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  edgeType: GraphEdgeType;
  label: string;
  isDirected: boolean;
  provenance: {
    sourceRecordId?: string;
    recordType: string;
    timestamp: string;
    confidence: number;
    evidenceDetails?: Record<string, any>;
  };
}

export interface InvestigationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    rootNodeId?: string;
    nodeCount: number;
    edgeCount: number;
    timeWindowStart?: string;
    timeWindowEnd?: string;
    generatedAt: string;
  };
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

export type BlastRadiusTier =
  | 'CONFIRMED_OBSERVED'
  | 'POTENTIALLY_EXPOSED'
  | 'PERIMETER_REACHABLE';

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

export type RiskTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RiskImpactBreakdown {
  score: number;
  severityScore: number;
  assetCriticalityScore: number;
  environmentModifier: number;
  blastRadiusScore: number;
  assumedDefaults: string[];
}

export interface RiskConfidenceBreakdown {
  score: number;
  correlationScore: number;
  velocityScore: number;
  detectionFidelityScore: number;
  rawEventCount: number;
  dampenedFactor: number;
}

export interface RiskRecencyBreakdown {
  elapsedHours: number;
  decayMultiplier: number;
  lastSeenTimestamp: string;
}

export interface RiskScoreBreakdown {
  score: number;
  tier: RiskTier;
  components: {
    impact: RiskImpactBreakdown;
    confidence: RiskConfidenceBreakdown;
    recency: RiskRecencyBreakdown;
  };
  explanation: string[];
  version: string;
  evaluatedAt: string;
}

export interface PrioritizedIncidentItem {
  id: string;
  code: string;
  title: string;
  severity: Severity;
  riskScore: number;
  riskTier: RiskTier;
  riskFactors: RiskScoreBreakdown;
  createdAt: string;
  updatedAt: string;
}

