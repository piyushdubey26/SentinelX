/**
 * SentinelX Milestone 2.4 - Explainable Incident Risk Scoring & Prioritization Types
 */

import { EventSeverity } from '../events/entities/security-event.entity';
import { AssetCriticality, AssetEnvironment } from '../assets/entities/asset.entity';

export enum RiskTier {
  CRITICAL = 'CRITICAL', // 80.00 - 100.00
  HIGH = 'HIGH',         // 60.00 - 79.99
  MEDIUM = 'MEDIUM',     // 35.00 - 59.99
  LOW = 'LOW',           // 0.00 - 34.99
}

export interface RiskScoringWeights {
  // Impact component weights (sum to 1.0)
  impactSeverityWeight: number;      // default: 0.40
  impactCriticalityWeight: number;   // default: 0.40
  impactBlastRadiusWeight: number;   // default: 0.20

  // Confidence component weights (sum to 1.0)
  confidenceCorrelationWeight: number; // default: 0.45
  confidenceVelocityWeight: number;    // default: 0.30
  confidenceDetectionWeight: number;   // default: 0.25

  // Event velocity dampening parameters
  velocitySaturationCount: number;    // default: 50 (logarithmic curve saturation point)

  // Temporal decay half-life in hours
  temporalHalfLifeHours: number;      // default: 24.0 (decay floor: 0.50)
  temporalDecayFloor: number;         // default: 0.50
}

export const DEFAULT_RISK_CONFIG: {
  version: string;
  weights: RiskScoringWeights;
} = {
  version: '1.0.0',
  weights: {
    impactSeverityWeight: 0.40,
    impactCriticalityWeight: 0.40,
    impactBlastRadiusWeight: 0.20,

    confidenceCorrelationWeight: 0.45,
    confidenceVelocityWeight: 0.30,
    confidenceDetectionWeight: 0.25,

    velocitySaturationCount: 50,
    temporalHalfLifeHours: 24.0,
    temporalDecayFloor: 0.50,
  },
};

export interface RiskImpactBreakdown {
  score: number;                    // 0.00 - 100.00
  severityScore: number;            // 0.00 - 1.00
  assetCriticalityScore: number;     // 0.00 - 1.00
  environmentModifier: number;      // 0.70 - 1.00
  blastRadiusScore: number;         // 0.00 - 1.00
  assumedDefaults: string[];        // flags if any missing data was imputed
}

export interface RiskConfidenceBreakdown {
  score: number;                    // 0.20 - 1.00
  correlationScore: number;         // 0.00 - 1.00
  velocityScore: number;            // 0.00 - 1.00
  detectionFidelityScore: number;   // 0.00 - 1.00
  rawEventCount: number;
  dampenedFactor: number;
}

export interface RiskRecencyBreakdown {
  elapsedHours: number;
  decayMultiplier: number;          // 0.50 - 1.00
  lastSeenTimestamp: string;
}

export interface RiskScoreBreakdown {
  score: number;                    // Final calibrated score: 0.00 - 100.00
  tier: RiskTier;
  components: {
    impact: RiskImpactBreakdown;
    confidence: RiskConfidenceBreakdown;
    recency: RiskRecencyBreakdown;
  };
  explanation: string[];             // Transparent human-readable audit trail
  version: string;
  evaluatedAt: string;
}

export interface RiskEvaluationInput {
  incidentId: string;
  severity: EventSeverity;
  sourceIp?: string;
  assetCriticality?: AssetCriticality;
  assetEnvironment?: AssetEnvironment;
  correlationConfidence?: number;   // 0.0 - 1.0
  eventCount?: number;
  detectionRuleSeverity?: EventSeverity;
  blastRadiusCriticalAssets?: number;
  blastRadiusTotalNodes?: number;
  lastSeen?: Date | string;
}

export interface PrioritizedIncidentItem {
  id: string;
  code: string;
  title: string;
  severity: EventSeverity;
  riskScore: number;
  riskTier: RiskTier;
  riskFactors: RiskScoreBreakdown;
  createdAt: string;
  updatedAt: string;
}
