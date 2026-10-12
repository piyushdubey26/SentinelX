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
