import {
  CandidateClusterState,
  CandidateIncidentStatus,
  CorrelationEvaluationResult,
  CorrelationFactor,
  CorrelationFactorType,
  CorrelationScoringConfig,
  DEFAULT_CORRELATION_CONFIG,
} from './correlation.types';
import { SecurityEvent, EventSeverity } from '../events/entities/security-event.entity';
import { Detection } from '../detections/entities/detection.entity';

/**
 * Valid attack chain progression sequences (MITRE ATT&CK kill-chain transitions)
 */
const ATTACK_PROGRESSION_SEQUENCES: Set<string> = new Set([
  'AUTH_FAILURE->AUTH_SUCCESS',
  'AUTH_FAILURE->PRIVILEGE_ESCALATION',
  'AUTH_SUCCESS->PRIVILEGE_ESCALATION',
  'PRIVILEGE_ESCALATION->SUSPICIOUS_PROCESS',
  'PRIVILEGE_ESCALATION->DATA_EXFILTRATION',
  'SUSPICIOUS_PROCESS->DATA_EXFILTRATION',
  'PORT_SCAN->AUTH_FAILURE',
  'PORT_SCAN->EXPLOIT_ATTEMPT',
  'EXPLOIT_ATTEMPT->PRIVILEGE_ESCALATION',
]);

/**
 * High-performance stateful Correlation Engine
 * Maintains an in-memory compound sliding-window index with strict anti-IP-bleeding safeguards.
 */
export class CorrelationEngine {
  private readonly config: CorrelationScoringConfig;

  // Active candidate clusters indexed by clusterId
  private readonly clusters = new Map<string, CandidateClusterState>();

  // Inverted indexes for entity lookup
  private readonly userIndex = new Map<string, Set<string>>(); // targetUser -> clusterIds
  private readonly assetIndex = new Map<string, Set<string>>(); // assetId -> clusterIds
  private readonly ipIndex = new Map<string, Set<string>>(); // sourceIp -> clusterIds

  constructor(config: CorrelationScoringConfig = DEFAULT_CORRELATION_CONFIG) {
    this.config = config;
  }

  getConfig(): CorrelationScoringConfig {
    return { ...this.config };
  }

  getClusterCount(): number {
    return this.clusters.size;
  }

  getCluster(clusterId: string): CandidateClusterState | undefined {
    return this.clusters.get(clusterId);
  }

  getAllActiveClusters(): CandidateClusterState[] {
    return Array.from(this.clusters.values()).filter(
      (c) => c.status === CandidateIncidentStatus.CANDIDATE,
    );
  }

  /**
   * Evaluates an incoming event against active clusters.
   * Finds candidate clusters and selects the best matching cluster if score >= threshold.
   */
  evaluateEvent(
    event: SecurityEvent,
    detection?: Detection,
  ): {
    matchedCluster?: CandidateClusterState;
    evaluation: CorrelationEvaluationResult;
    candidateClusterIds: string[];
  } {
    const timestampMs = new Date(event.eventTimestamp).getTime();

    // 1. Candidate Retrieval: O(1) average lookup via entity indexes (Identity and Asset anchors)
    const { candidateIds, hasSharedIpOnly, sampleIpClusterId } = this.findCandidateClusterIds(event);

    let bestCluster: CandidateClusterState | undefined = undefined;
    let bestEvaluation: CorrelationEvaluationResult = {
      isCorrelated: false,
      score: 0,
      factors: [],
      rejectedFactors: [],
      explanation: 'No correlation found with active incident clusters.',
      suggestedSeverity: event.severity || EventSeverity.MEDIUM,
      shouldAutoPromote: false,
    };

    for (const clusterId of candidateIds) {
      const cluster = this.clusters.get(clusterId);
      if (!cluster || cluster.status !== CandidateIncidentStatus.CANDIDATE) {
        continue;
      }

      // Check temporal sliding window: |eventTime - clusterWindow| <= slidingWindowSeconds
      const minBound = cluster.firstSeen - this.config.slidingWindowSeconds * 1000;
      const maxBound = cluster.lastSeen + this.config.slidingWindowSeconds * 1000;
      if (timestampMs < minBound || timestampMs > maxBound) {
        continue; // Event is outside cluster temporal window
      }

      const evalResult = this.evaluateMatch(event, cluster, detection);
      if (evalResult.isCorrelated) {
        if (
          evalResult.score > bestEvaluation.score ||
          (evalResult.score === bestEvaluation.score &&
            bestCluster &&
            cluster.lastSeen > bestCluster.lastSeen)
        ) {
          bestEvaluation = evalResult;
          bestCluster = cluster;
        }
      }
    }

    // If no primary cluster matched, check if IP matched an existing cluster to provide anti-IP-bleeding evidence
    if (!bestCluster && hasSharedIpOnly && sampleIpClusterId) {
      const sampleCluster = this.clusters.get(sampleIpClusterId);
      if (sampleCluster) {
        bestEvaluation = this.evaluateMatch(event, sampleCluster, detection);
      }
    }

    return {
      matchedCluster: bestCluster,
      evaluation: bestEvaluation,
      candidateClusterIds: candidateIds,
    };
  }

  /**
   * Matches an event against a specific cluster using the multi-attribute rubric.
   * Strictly enforces Anti-IP-Bleeding rules.
   */
  evaluateMatch(
    event: SecurityEvent,
    cluster: CandidateClusterState,
    detection?: Detection,
  ): CorrelationEvaluationResult {
    const factors: CorrelationFactor[] = [];
    const rejectedFactors: CorrelationFactor[] = [];
    let totalScore = 0;

    // 1. Shared Identity Dimension (Weight: 0.35)
    let identityMatched = false;
    if (event.targetUser && cluster.primaryUser) {
      if (event.targetUser.toLowerCase() === cluster.primaryUser.toLowerCase()) {
        identityMatched = true;
        const weight = this.config.weights.sharedIdentity;
        factors.push({
          factorType: CorrelationFactorType.SHARED_IDENTITY,
          weight,
          contribution: weight,
          description: `Shared target identity '${event.targetUser}' matched active cluster.`,
          evidence: { targetUser: event.targetUser, clusterUser: cluster.primaryUser },
        });
        totalScore += weight;
      }
    }

    // 2. Shared Asset Dimension (Weight: 0.30)
    let assetMatched = false;
    if (event.assetId && cluster.primaryAssetId) {
      if (event.assetId === cluster.primaryAssetId) {
        assetMatched = true;
        const weight = this.config.weights.sharedAsset;
        factors.push({
          factorType: CorrelationFactorType.SHARED_ASSET,
          weight,
          contribution: weight,
          description: `Shared target asset '${event.assetId}' matched active cluster.`,
          evidence: { assetId: event.assetId, clusterAssetId: cluster.primaryAssetId },
        });
        totalScore += weight;
      }
    }

    // 3. Attack Chain Progression (Weight: 0.25)
    let progressionMatched = false;
    for (const prevType of cluster.eventTypes) {
      const transitionKey = `${prevType}->${event.eventType}`;
      if (ATTACK_PROGRESSION_SEQUENCES.has(transitionKey)) {
        progressionMatched = true;
        const weight = this.config.weights.attackProgression;
        factors.push({
          factorType: CorrelationFactorType.ATTACK_TECHNIQUE_PROGRESSION,
          weight,
          contribution: weight,
          description: `Observed kill-chain attack progression: ${transitionKey}.`,
          evidence: { previousEventType: prevType, incomingEventType: event.eventType, transitionKey },
        });
        totalScore += weight;
        break; // Count once
      }
    }

    // 4. Source IP Evaluation & ANTI-IP-BLEEDING Check
    const ipMatches = event.sourceIp && cluster.primarySourceIp && event.sourceIp === cluster.primarySourceIp;

    if (ipMatches) {
      // Check if IP is accompanied by at least one primary anchor (identity or asset or progression)
      const hasPrimaryAnchor = identityMatched || assetMatched || progressionMatched;

      if (hasPrimaryAnchor) {
        // IP serves as reinforcing network evidence
        const weight = this.config.weights.networkTargetPair;
        factors.push({
          factorType: CorrelationFactorType.NETWORK_TARGET_PAIR,
          weight,
          contribution: weight,
          description: `Matching source IP '${event.sourceIp}' reinforced by shared identity or asset.`,
          evidence: {
            sourceIp: event.sourceIp,
            clusterSourceIp: cluster.primarySourceIp,
            reinforcedBy: identityMatched ? 'IDENTITY' : assetMatched ? 'ASSET' : 'ATTACK_PROGRESSION',
          },
        });
        totalScore += weight;
      } else {
        // CRITICAL ANTI-IP-BLEEDING RULE:
        // Shared IP alone with DIFFERENT or MISSING user and asset MUST NOT MERGE
        rejectedFactors.push({
          factorType: CorrelationFactorType.SHARED_SOURCE_IP_REJECTED,
          weight: 0,
          contribution: 0,
          description: this.config.antiIpBleeding.rejectionReason,
          evidence: {
            sharedIp: event.sourceIp,
            eventUser: event.targetUser || null,
            clusterUser: cluster.primaryUser || null,
            eventAsset: event.assetId || null,
            clusterAsset: cluster.primaryAssetId || null,
          },
        });
      }
    }

    // Cap score at 1.0 (ranking signal)
    const normalizedScore = Math.min(1.0, Math.round(totalScore * 1000) / 1000);
    const isCorrelated = normalizedScore >= this.config.correlationThreshold;

    // Severity suggestion based on detection or max severity
    let suggestedSeverity = cluster.severity;
    if (detection && detection.severity === EventSeverity.CRITICAL) {
      suggestedSeverity = EventSeverity.CRITICAL;
    } else if (event.severity === EventSeverity.CRITICAL) {
      suggestedSeverity = EventSeverity.CRITICAL;
    } else if (event.severity === EventSeverity.HIGH && suggestedSeverity !== EventSeverity.CRITICAL) {
      suggestedSeverity = EventSeverity.HIGH;
    }

    const shouldAutoPromote =
      normalizedScore >= this.config.autoPromotionThreshold ||
      (isCorrelated && progressionMatched && suggestedSeverity === EventSeverity.CRITICAL);

    // Human & machine explainability narrative
    const explanation = this.buildExplanation(
      isCorrelated,
      normalizedScore,
      factors,
      rejectedFactors,
      event,
      cluster,
    );

    return {
      isCorrelated,
      score: normalizedScore,
      factors,
      rejectedFactors,
      explanation,
      suggestedSeverity,
      shouldAutoPromote,
    };
  }

  /**
   * Ingests and updates cluster state incrementally.
   * Returns the updated or newly created candidate cluster state.
   */
  ingest(
    event: SecurityEvent,
    detection?: Detection,
    candidateIdGenerator?: () => string,
  ): {
    cluster: CandidateClusterState;
    isNewCluster: boolean;
    evaluation: CorrelationEvaluationResult;
  } {
    const timestampMs = new Date(event.eventTimestamp).getTime();
    const evalResult = this.evaluateEvent(event, detection);

    if (evalResult.matchedCluster && evalResult.evaluation.isCorrelated) {
      // Merge event into existing cluster
      const cluster = evalResult.matchedCluster;
      cluster.eventIds.push(event.id);
      if (detection) {
        cluster.detectionIds.push(detection.id);
      }
      cluster.firstSeen = Math.min(cluster.firstSeen, timestampMs);
      cluster.lastSeen = Math.max(cluster.lastSeen, timestampMs);
      if (!cluster.eventTypes.includes(event.eventType)) {
        cluster.eventTypes.push(event.eventType);
      }
      cluster.confidenceScore = Math.max(cluster.confidenceScore, evalResult.evaluation.score);
      cluster.severity = evalResult.evaluation.suggestedSeverity;
      const combinedFactors = [...cluster.factors, ...evalResult.evaluation.factors];
      cluster.factors = combinedFactors.slice(-10);
      cluster.explanation = evalResult.evaluation.explanation;

      // Update secondary indexes if cluster acquired new identity/asset
      if (!cluster.primaryUser && event.targetUser) {
        cluster.primaryUser = event.targetUser;
        this.addIndex(this.userIndex, event.targetUser, cluster.candidateId);
      }
      if (!cluster.primaryAssetId && event.assetId) {
        cluster.primaryAssetId = event.assetId;
        this.addIndex(this.assetIndex, event.assetId, cluster.candidateId);
      }

      return { cluster, isNewCluster: false, evaluation: evalResult.evaluation };
    }

    // No matching cluster found -> initialize new candidate cluster
    const newId = candidateIdGenerator ? candidateIdGenerator() : this.generateUUID();
    const title = this.buildClusterTitle(event, detection);
    const summary = this.buildClusterSummary(event, detection);

    const initialFactors: CorrelationFactor[] = [];
    if (detection) {
      initialFactors.push({
        factorType: CorrelationFactorType.ATTACK_TECHNIQUE_PROGRESSION,
        weight: 0.25,
        contribution: 0.25,
        description: `Detection rule '${detection.ruleName}' triggered cluster creation.`,
        evidence: { ruleId: detection.ruleId, ruleName: detection.ruleName },
      });
    }

    const initialScore = detection ? 0.60 : event.severity === EventSeverity.HIGH ? 0.40 : 0.20;

    const newCluster: CandidateClusterState = {
      candidateId: newId,
      title,
      summary,
      confidenceScore: initialScore,
      severity: detection ? detection.severity : event.severity || EventSeverity.MEDIUM,
      status: CandidateIncidentStatus.CANDIDATE,
      primaryUser: event.targetUser || undefined,
      primarySourceIp: event.sourceIp,
      primaryAssetId: event.assetId || undefined,
      eventIds: [event.id],
      detectionIds: detection ? [detection.id] : [],
      firstSeen: timestampMs,
      lastSeen: timestampMs,
      eventTypes: [event.eventType],
      factors: initialFactors,
      explanation: `Initialized new candidate incident cluster from event ${event.eventType} on ${event.sourceIp}.`,
    };

    // Store in primary map
    this.clusters.set(newId, newCluster);

    // Index by entity attributes for O(1) amortized lookup
    if (event.targetUser) {
      this.addIndex(this.userIndex, event.targetUser, newId);
    }
    if (event.assetId) {
      this.addIndex(this.assetIndex, event.assetId, newId);
    }
    if (event.sourceIp) {
      this.addIndex(this.ipIndex, event.sourceIp, newId);
    }

    return {
      cluster: newCluster,
      isNewCluster: true,
      evaluation: {
        isCorrelated: false,
        score: initialScore,
        factors: initialFactors,
        rejectedFactors: evalResult.evaluation.rejectedFactors,
        explanation: newCluster.explanation,
        suggestedSeverity: newCluster.severity,
        shouldAutoPromote: false,
      },
    };
  }

  /**
   * Evicts expired clusters from memory based on sliding window TTL.
   * Complexity: O(E * deg) where E is number of expired clusters.
   */
  evictExpired(nowMs: number = Date.now()): string[] {
    const cutoff = nowMs - this.config.slidingWindowSeconds * 1000;
    const evictedIds: string[] = [];

    for (const [id, cluster] of this.clusters.entries()) {
      if (cluster.lastSeen < cutoff) {
        evictedIds.push(id);
        this.clusters.delete(id);

        if (cluster.primaryUser) {
          this.removeIndex(this.userIndex, cluster.primaryUser, id);
        }
        if (cluster.primaryAssetId) {
          this.removeIndex(this.assetIndex, cluster.primaryAssetId, id);
        }
        if (cluster.primarySourceIp) {
          this.removeIndex(this.ipIndex, cluster.primarySourceIp, id);
        }
      }
    }

    return evictedIds;
  }

  /**
   * Direct comparison of two distinct events for explainability testing.
   */
  compareEvents(
    eventA: SecurityEvent,
    eventB: SecurityEvent,
  ): CorrelationEvaluationResult {
    const dummyCluster: CandidateClusterState = {
      candidateId: 'test-cluster',
      title: 'Comparison Cluster',
      summary: 'Comparison Cluster',
      confidenceScore: 0.5,
      severity: eventA.severity || EventSeverity.MEDIUM,
      status: CandidateIncidentStatus.CANDIDATE,
      primaryUser: eventA.targetUser,
      primarySourceIp: eventA.sourceIp,
      primaryAssetId: eventA.assetId,
      eventIds: [eventA.id],
      detectionIds: [],
      firstSeen: new Date(eventA.eventTimestamp).getTime(),
      lastSeen: new Date(eventA.eventTimestamp).getTime(),
      eventTypes: [eventA.eventType],
      factors: [],
      explanation: '',
    };

    return this.evaluateMatch(eventB, dummyCluster);
  }

  // --- Private Helper Methods ---

  private findCandidateClusterIds(event: SecurityEvent): {
    candidateIds: string[];
    hasSharedIpOnly: boolean;
    sampleIpClusterId?: string;
  } {
    const candidateSet = new Set<string>();

    if (event.targetUser) {
      const userClusters = this.userIndex.get(event.targetUser.toLowerCase());
      if (userClusters) {
        for (const id of userClusters) candidateSet.add(id);
      }
    }

    if (event.assetId) {
      const assetClusters = this.assetIndex.get(event.assetId);
      if (assetClusters) {
        for (const id of assetClusters) candidateSet.add(id);
      }
    }

    let hasSharedIpOnly = false;
    let sampleIpClusterId: string | undefined = undefined;

    if (event.sourceIp) {
      const ipClusters = this.ipIndex.get(event.sourceIp);
      if (ipClusters && ipClusters.size > 0) {
        hasSharedIpOnly = true;
        sampleIpClusterId = ipClusters.values().next().value;
      }
    }

    return {
      candidateIds: Array.from(candidateSet),
      hasSharedIpOnly,
      sampleIpClusterId,
    };
  }

  private addIndex(indexMap: Map<string, Set<string>>, key: string, id: string): void {
    const normalizedKey = key.toLowerCase();
    let set = indexMap.get(normalizedKey);
    if (!set) {
      set = new Set<string>();
      indexMap.set(normalizedKey, set);
    }
    set.add(id);
  }

  private removeIndex(indexMap: Map<string, Set<string>>, key: string, id: string): void {
    const normalizedKey = key.toLowerCase();
    const set = indexMap.get(normalizedKey);
    if (set) {
      set.delete(id);
      if (set.size === 0) {
        indexMap.delete(normalizedKey);
      }
    }
  }

  private buildClusterTitle(event: SecurityEvent, detection?: Detection): string {
    if (detection) {
      return `Correlated Activity: ${detection.ruleName} [${event.targetUser || event.sourceIp}]`;
    }
    return `Candidate Incident: Suspicious ${event.eventType} on [${event.sourceIp}]`;
  }

  private buildClusterSummary(event: SecurityEvent, detection?: Detection): string {
    if (detection) {
      return `Aggregated cluster triggered by rule ${detection.ruleId} involving user '${event.targetUser || 'unknown'}' and host ${event.sourceIp}.`;
    }
    return `Aggregated cluster initiated by ${event.eventType} from ${event.sourceIp}.`;
  }

  private buildExplanation(
    isCorrelated: boolean,
    score: number,
    factors: CorrelationFactor[],
    rejectedFactors: CorrelationFactor[],
    event: SecurityEvent,
    cluster: CandidateClusterState,
  ): string {
    if (isCorrelated) {
      const factorDescs = factors.map((f) => f.description).join(' ');
      return `Correlated with cluster '${cluster.candidateId}' (Confidence Score: ${score.toFixed(3)}). Factors: ${factorDescs}`;
    }

    if (rejectedFactors.length > 0) {
      const rejectionDescs = rejectedFactors.map((r) => r.description).join(' ');
      return `Correlation rejected (Score: ${score.toFixed(3)} < threshold ${this.config.correlationThreshold}). Safeguard: ${rejectionDescs}`;
    }

    return `Event does not meet correlation threshold (Score: ${score.toFixed(3)} < ${this.config.correlationThreshold}).`;
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}
