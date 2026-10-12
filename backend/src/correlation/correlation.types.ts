import { EventSeverity } from '../events/entities/security-event.entity';

export enum CandidateIncidentStatus {
  CANDIDATE = 'CANDIDATE',
  PROMOTED = 'PROMOTED',
  DISMISSED = 'DISMISSED',
}

export enum CorrelationFactorType {
  SHARED_IDENTITY = 'SHARED_IDENTITY',
  SHARED_ASSET = 'SHARED_ASSET',
  ATTACK_TECHNIQUE_PROGRESSION = 'ATTACK_TECHNIQUE_PROGRESSION',
  NETWORK_TARGET_PAIR = 'NETWORK_TARGET_PAIR',
  SHARED_SOURCE_IP_REJECTED = 'SHARED_SOURCE_IP_REJECTED',
}

export interface CorrelationFactor {
  factorType: CorrelationFactorType;
  weight: number;
  contribution: number;
  description: string;
  evidence: Record<string, any>;
}

export interface CorrelationScoringConfig {
  version: string;
  slidingWindowSeconds: number;
  correlationThreshold: number;
  autoPromotionThreshold: number;
  weights: {
    sharedIdentity: number;
    sharedAsset: number;
    attackProgression: number;
    networkTargetPair: number;
  };
  antiIpBleeding: {
    allowIpOnlyCorrelation: boolean;
    rejectionReason: string;
  };
}

export const DEFAULT_CORRELATION_CONFIG: CorrelationScoringConfig = {
  version: '1.0.0',
  slidingWindowSeconds: 900, // 15 minutes
  correlationThreshold: 0.50, // Minimum score to link event to candidate incident
  autoPromotionThreshold: 0.85, // Score to automatically trigger confirmed incident creation
  weights: {
    sharedIdentity: 0.35,
    sharedAsset: 0.25,
    attackProgression: 0.25,
    networkTargetPair: 0.15,
  },
  antiIpBleeding: {
    allowIpOnlyCorrelation: false,
    rejectionReason: 'ANTI_IP_BLEEDING: Shared source IP alone is insufficient for correlation across NAT/VPN/proxy environments.',
  },
};

export interface CorrelationEvaluationResult {
  isCorrelated: boolean;
  score: number;
  factors: CorrelationFactor[];
  rejectedFactors: CorrelationFactor[];
  explanation: string;
  suggestedSeverity: EventSeverity;
  shouldAutoPromote: boolean;
}

export interface CandidateClusterState {
  candidateId: string;
  title: string;
  summary: string;
  confidenceScore: number;
  severity: EventSeverity;
  status: CandidateIncidentStatus;
  primaryUser?: string;
  primarySourceIp?: string;
  primaryAssetId?: string;
  eventIds: string[];
  detectionIds: string[];
  firstSeen: number; // epoch ms
  lastSeen: number; // epoch ms
  eventTypes: string[];
  factors: CorrelationFactor[];
  explanation: string;
}
