import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Incident, IncidentStatus } from '../incidents/entities/incident.entity';
import { Asset, AssetCriticality, AssetEnvironment } from '../assets/entities/asset.entity';
import { CandidateIncident } from '../correlation/entities/candidate-incident.entity';
import { Detection } from '../detections/entities/detection.entity';
import { EventSeverity } from '../events/entities/security-event.entity';
import { AuditService } from '../audit/audit.service';
import {
  DEFAULT_RISK_CONFIG,
  RiskEvaluationInput,
  RiskScoreBreakdown,
  RiskTier,
  RiskImpactBreakdown,
  RiskConfidenceBreakdown,
  RiskRecencyBreakdown,
  PrioritizedIncidentItem,
} from './risk.types';
import { RiskPriorityQueue } from './dsa/priority-queue';

@Injectable()
export class RiskScoringService {
  private readonly logger = new Logger(RiskScoringService.name);
  private config = DEFAULT_RISK_CONFIG;

  constructor(
    @InjectRepository(Incident)
    private readonly incidentRepo: Repository<Incident>,
    @InjectRepository(Asset)
    private readonly assetRepo: Repository<Asset>,
    @InjectRepository(CandidateIncident)
    private readonly candidateRepo: Repository<CandidateIncident>,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Pure deterministic mathematical risk evaluation function.
   * Separates Impact from Confidence, applies sublinear velocity dampening,
   * and factors in exponential recency decay.
   */
  evaluateRisk(
    input: RiskEvaluationInput,
    evaluationTimestamp: Date = new Date(),
  ): RiskScoreBreakdown {
    const { weights, version } = this.config;
    const assumedDefaults: string[] = [];
    const explanation: string[] = [];

    // -------------------------------------------------------------
    // 1. IMPACT COMPONENT (0.00 - 100.00)
    // -------------------------------------------------------------
    // A. Detection Severity (Weight: 0.40)
    let severityScore = 0.50; // Default MEDIUM
    switch (input.severity) {
      case EventSeverity.CRITICAL:
        severityScore = 1.00;
        break;
      case EventSeverity.HIGH:
        severityScore = 0.75;
        break;
      case EventSeverity.MEDIUM:
        severityScore = 0.50;
        break;
      case EventSeverity.LOW:
        severityScore = 0.25;
        break;
      case EventSeverity.INFO:
        severityScore = 0.10;
        break;
    }

    // B. Asset Criticality & Environment (Weight: 0.40)
    let assetCriticalityScore = 0.50; // Default MEDIUM if unassigned
    if (!input.assetCriticality) {
      assumedDefaults.push('Asset criticality unassigned; defaulted to baseline MEDIUM (0.50)');
    } else {
      switch (input.assetCriticality) {
        case AssetCriticality.CRITICAL:
          assetCriticalityScore = 1.00;
          break;
        case AssetCriticality.HIGH:
          assetCriticalityScore = 0.75;
          break;
        case AssetCriticality.MEDIUM:
          assetCriticalityScore = 0.50;
          break;
        case AssetCriticality.LOW:
          assetCriticalityScore = 0.25;
          break;
      }
    }

    let environmentModifier = 1.00; // Default PRODUCTION
    if (input.assetEnvironment) {
      switch (input.assetEnvironment) {
        case AssetEnvironment.PRODUCTION:
          environmentModifier = 1.00;
          break;
        case AssetEnvironment.STAGING:
          environmentModifier = 0.85;
          break;
        case AssetEnvironment.DEVELOPMENT:
          environmentModifier = 0.70;
          break;
      }
    }

    const effectiveAssetScore = assetCriticalityScore * environmentModifier;

    // C. Blast Radius Reachability (Weight: 0.20)
    let blastRadiusScore = 0.25; // Safe baseline if graph uncomputed
    if (
      input.blastRadiusCriticalAssets !== undefined ||
      input.blastRadiusTotalNodes !== undefined
    ) {
      const critCount = input.blastRadiusCriticalAssets || 0;
      const totalCount = input.blastRadiusTotalNodes || 0;
      // Formula: each critical asset adds 0.50, each reachable node adds 0.05, normalized to max 2.0
      blastRadiusScore = Math.min(1.0, (critCount * 0.50 + totalCount * 0.05) / 2.0);
    } else {
      assumedDefaults.push('Blast radius uncomputed; defaulted to baseline exposure (0.25)');
    }

    const rawImpact =
      weights.impactSeverityWeight * severityScore +
      weights.impactCriticalityWeight * effectiveAssetScore +
      weights.impactBlastRadiusWeight * blastRadiusScore;
    const impactScore = Math.min(100.0, Math.max(0.0, rawImpact * 100.0));

    // -------------------------------------------------------------
    // 2. CONFIDENCE COMPONENT (0.20 - 1.00)
    // -------------------------------------------------------------
    // A. Correlation Confidence (Weight: 0.45)
    let correlationScore = 0.60; // Baseline for standalone single-rule alert
    if (input.correlationConfidence !== undefined) {
      correlationScore = Math.min(1.0, Math.max(0.0, input.correlationConfidence));
    } else {
      assumedDefaults.push('Correlation confidence unassigned; defaulted to standalone baseline (0.60)');
    }

    // B. Event Velocity with Sublinear Logarithmic Dampening (Weight: 0.30)
    // Invariant: 10,000 events must NEVER inflate score to infinity
    const rawEventCount = Math.max(1, input.eventCount || 1);
    const satCount = weights.velocitySaturationCount; // e.g. 50
    const velocityScore = Math.min(
      1.0,
      Math.log(1 + rawEventCount) / Math.log(1 + satCount),
    );

    // C. Detection Rule Fidelity (Weight: 0.25)
    let detectionFidelityScore = 0.80; // Baseline rule match
    if (input.detectionRuleSeverity === EventSeverity.CRITICAL) {
      detectionFidelityScore = 1.00;
    } else if (input.detectionRuleSeverity === EventSeverity.HIGH) {
      detectionFidelityScore = 0.90;
    } else if (input.detectionRuleSeverity) {
      detectionFidelityScore = 0.75;
    }

    const confidenceScore =
      weights.confidenceCorrelationWeight * correlationScore +
      weights.confidenceVelocityWeight * velocityScore +
      weights.confidenceDetectionWeight * detectionFidelityScore;

    // -------------------------------------------------------------
    // 3. RECENCY DECAY COMPONENT (0.50 - 1.00)
    // -------------------------------------------------------------
    const lastSeenDate = input.lastSeen
      ? new Date(input.lastSeen)
      : evaluationTimestamp;
    const elapsedMs = Math.max(0, evaluationTimestamp.getTime() - lastSeenDate.getTime());
    const elapsedHours = elapsedMs / (1000 * 60 * 60);

    // Half-life exponential decay: e^(-lambda * t) where lambda = ln(2) / halfLife
    const lambda = Math.LN2 / weights.temporalHalfLifeHours;
    const rawDecay = Math.exp(-lambda * elapsedHours);
    const decayMultiplier = Math.max(weights.temporalDecayFloor, rawDecay);

    // -------------------------------------------------------------
    // 4. COMBINED CALIBRATED RISK SCORE
    // -------------------------------------------------------------
    // Confidence acts as a scaling coefficient: (0.30 + 0.70 * confidence)
    // Even low-confidence high-impact incidents get a minimum 30% baseline
    const confidenceMultiplier = 0.30 + 0.70 * confidenceScore;
    const finalScore = parseFloat(
      (impactScore * confidenceMultiplier * decayMultiplier).toFixed(2),
    );

    // -------------------------------------------------------------
    // 5. RISK TIER
    // -------------------------------------------------------------
    let tier: RiskTier;
    if (finalScore >= 80.0) {
      tier = RiskTier.CRITICAL;
    } else if (finalScore >= 60.0) {
      tier = RiskTier.HIGH;
    } else if (finalScore >= 35.0) {
      tier = RiskTier.MEDIUM;
    } else {
      tier = RiskTier.LOW;
    }

    // -------------------------------------------------------------
    // 6. TRANSPARENT AUDIT TRAIL / EXPLANATIONS
    // -------------------------------------------------------------
    explanation.push(
      `Risk Score: ${finalScore.toFixed(2)}/100 (${tier} Tier). Evaluated by RiskEngine v${version}.`,
    );
    explanation.push(
      `Impact: ${impactScore.toFixed(1)}/100 (Severity: ${input.severity}, Asset: ${
        input.assetCriticality || 'MEDIUM (Default)'
      } on ${input.assetEnvironment || 'PRODUCTION'}, Blast: ${(blastRadiusScore * 100).toFixed(0)}%).`,
    );
    explanation.push(
      `Confidence: ${(confidenceScore * 100).toFixed(1)}% (Correlation: ${(
        correlationScore * 100
      ).toFixed(0)}%, Velocity: ${(velocityScore * 100).toFixed(0)}% from ${rawEventCount} events, Fidelity: ${(
        detectionFidelityScore * 100
      ).toFixed(0)}%).`,
    );
    if (elapsedHours > 1.0) {
      explanation.push(
        `Temporal Recency: ${(decayMultiplier * 100).toFixed(1)}% multiplier applied after ${elapsedHours.toFixed(1)}h elapsed.`,
      );
    } else {
      explanation.push(`Temporal Recency: Active / Emerging (100% recency multiplier).`);
    }

    if (assumedDefaults.length > 0) {
      explanation.push(`Assumptions: ${assumedDefaults.join('; ')}.`);
    }

    const impactBreakdown: RiskImpactBreakdown = {
      score: parseFloat(impactScore.toFixed(2)),
      severityScore: parseFloat(severityScore.toFixed(2)),
      assetCriticalityScore: parseFloat(assetCriticalityScore.toFixed(2)),
      environmentModifier: parseFloat(environmentModifier.toFixed(2)),
      blastRadiusScore: parseFloat(blastRadiusScore.toFixed(2)),
      assumedDefaults,
    };

    const confidenceBreakdown: RiskConfidenceBreakdown = {
      score: parseFloat(confidenceScore.toFixed(3)),
      correlationScore: parseFloat(correlationScore.toFixed(3)),
      velocityScore: parseFloat(velocityScore.toFixed(3)),
      detectionFidelityScore: parseFloat(detectionFidelityScore.toFixed(3)),
      rawEventCount,
      dampenedFactor: parseFloat(velocityScore.toFixed(3)),
    };

    const recencyBreakdown: RiskRecencyBreakdown = {
      elapsedHours: parseFloat(elapsedHours.toFixed(2)),
      decayMultiplier: parseFloat(decayMultiplier.toFixed(3)),
      lastSeenTimestamp: lastSeenDate.toISOString(),
    };

    return {
      score: finalScore,
      tier,
      components: {
        impact: impactBreakdown,
        confidence: confidenceBreakdown,
        recency: recencyBreakdown,
      },
      explanation,
      version,
      evaluatedAt: evaluationTimestamp.toISOString(),
    };
  }

  /**
   * Recalculates and persists risk score for a single incident in PostgreSQL.
   */
  async calculateAndPersistIncidentRisk(incidentId: string): Promise<Incident> {
    const incident = await this.incidentRepo.findOne({
      where: [{ id: incidentId }, { code: incidentId }],
      relations: ['detection', 'assignedTo'],
    });

    if (!incident) {
      throw new NotFoundException(`Incident '${incidentId}' not found.`);
    }

    // Attempt to resolve asset by source IP
    let asset: Asset | null = null;
    if (incident.sourceIp) {
      asset = await this.assetRepo.findOne({
        where: { ipAddress: incident.sourceIp },
      });
    }

    // Check if there is an associated candidate cluster
    let candidate: CandidateIncident | null = null;
    candidate = await this.candidateRepo.findOne({
      where: { incidentId: incident.id },
    });

    const eventCount = candidate?.eventIds ? candidate.eventIds.length : (incident.detection?.triggerCount || 1);
    const correlationConfidence = candidate ? Number(candidate.confidenceScore) : undefined;

    const breakdown = this.evaluateRisk({
      incidentId: incident.id,
      severity: incident.severity,
      sourceIp: incident.sourceIp,
      assetCriticality: asset?.criticality,
      assetEnvironment: asset?.environment,
      correlationConfidence,
      eventCount,
      detectionRuleSeverity: incident.detection?.severity,
      lastSeen: incident.updatedAt || incident.createdAt,
    });

    incident.riskScore = breakdown.score;
    incident.riskTier = breakdown.tier;
    incident.riskFactors = breakdown;

    const saved = await this.incidentRepo.save(incident);

    await this.auditService.logAction({
      action: 'INCIDENT_RISK_EVALUATED',
      resourceType: 'INCIDENT',
      resourceId: saved.id,
      details: {
        code: saved.code,
        score: breakdown.score,
        tier: breakdown.tier,
      },
    });

    return saved;
  }

  /**
   * Returns Top-K risk-prioritized incidents using the O(N log K) PriorityQueue algorithm.
   */
  async getPrioritizedIncidents(
    limit = 20,
    status?: IncidentStatus,
  ): Promise<PrioritizedIncidentItem[]> {
    const query = this.incidentRepo.createQueryBuilder('incident')
      .leftJoinAndSelect('incident.detection', 'detection')
      .leftJoinAndSelect('incident.assignedTo', 'assignedTo');

    if (status) {
      query.andWhere('incident.status = :status', { status });
    }

    const allIncidents = await query.getMany();

    // Map to entries with priority
    const entries = allIncidents.map((inc) => ({
      item: {
        id: inc.id,
        code: inc.code,
        title: inc.title,
        severity: inc.severity,
        riskScore: Number(inc.riskScore || 0),
        riskTier: (inc.riskTier as RiskTier) || RiskTier.LOW,
        riskFactors: inc.riskFactors as RiskScoreBreakdown,
        createdAt: inc.createdAt.toISOString(),
        updatedAt: inc.updatedAt.toISOString(),
      },
      priority: Number(inc.riskScore || 0),
    }));

    // Use bounded Min-Heap of size K (O(N log K))
    return RiskPriorityQueue.topK(entries, limit);
  }

  /**
   * Recalculates risk scores across all open and active incidents.
   */
  async recalculateAllOpenIncidents(): Promise<{ evaluated: number; updated: number }> {
    const activeIncidents = await this.incidentRepo.find({
      where: [
        { status: IncidentStatus.OPEN },
        { status: IncidentStatus.INVESTIGATING },
      ],
      relations: ['detection'],
    });

    let updatedCount = 0;
    for (const inc of activeIncidents) {
      await this.calculateAndPersistIncidentRisk(inc.id);
      updatedCount++;
    }

    this.logger.log(`Recalculated risk scores for ${updatedCount} active incidents.`);
    return { evaluated: activeIncidents.length, updated: updatedCount };
  }

  /**
   * Returns the current scoring configuration.
   */
  getConfig() {
    return { ...this.config };
  }
}
