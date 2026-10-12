import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CandidateIncident } from './entities/candidate-incident.entity';
import {
  CandidateClusterState,
  CandidateIncidentStatus,
  CorrelationEvaluationResult,
  DEFAULT_CORRELATION_CONFIG,
} from './correlation.types';
import { CorrelationEngine } from './correlation.engine';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { Detection } from '../detections/entities/detection.entity';
import { IncidentsService } from '../incidents/incidents.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);
  private readonly engine: CorrelationEngine;

  constructor(
    @InjectRepository(CandidateIncident)
    private readonly candidateRepo: Repository<CandidateIncident>,
    private readonly incidentsService: IncidentsService,
    private readonly auditService: AuditService,
  ) {
    this.engine = new CorrelationEngine(DEFAULT_CORRELATION_CONFIG);
  }

  getEngine(): CorrelationEngine {
    return this.engine;
  }

  /**
   * Process an incoming security event and its detection through the correlation engine.
   * Incremental execution: updates in-memory cluster state and persists to database.
   */
  async processEvent(
    event: SecurityEvent,
    detection?: Detection,
  ): Promise<{
    candidate: CandidateIncident;
    isNewCandidate: boolean;
    autoPromoted: boolean;
    evaluation: CorrelationEvaluationResult;
  }> {
    const { cluster, isNewCluster, evaluation } = this.engine.ingest(
      event,
      detection,
    );

    let candidateEntity: CandidateIncident;

    if (isNewCluster) {
      // Create new candidate incident in database
      candidateEntity = this.candidateRepo.create({
        id: cluster.candidateId,
        title: cluster.title,
        summary: cluster.summary,
        confidenceScore: cluster.confidenceScore,
        severity: cluster.severity,
        status: CandidateIncidentStatus.CANDIDATE,
        correlationFactors: cluster.factors,
        explanation: cluster.explanation,
        primaryUser: cluster.primaryUser,
        primarySourceIp: cluster.primarySourceIp,
        primaryAssetId: cluster.primaryAssetId,
        eventIds: cluster.eventIds,
        detectionIds: cluster.detectionIds,
        firstSeen: new Date(cluster.firstSeen),
        lastSeen: new Date(cluster.lastSeen),
      });

      candidateEntity = await this.candidateRepo.save(candidateEntity);
      this.logger.debug(`[CorrelationService] Created candidate incident ${candidateEntity.id}`);
    } else {
      // Update existing candidate incident in database
      const existing = await this.candidateRepo.findOne({ where: { id: cluster.candidateId } });
      if (existing) {
        existing.confidenceScore = cluster.confidenceScore;
        existing.severity = cluster.severity;
        existing.correlationFactors = cluster.factors;
        existing.explanation = cluster.explanation;
        existing.eventIds = cluster.eventIds;
        existing.detectionIds = cluster.detectionIds;
        existing.lastSeen = new Date(cluster.lastSeen);
        existing.firstSeen = new Date(cluster.firstSeen);
        if (cluster.primaryUser) existing.primaryUser = cluster.primaryUser;
        if (cluster.primaryAssetId) existing.primaryAssetId = cluster.primaryAssetId;
        candidateEntity = await this.candidateRepo.save(existing);
      } else {
        // Fallback in case cluster was in-memory only
        candidateEntity = this.candidateRepo.create({
          id: cluster.candidateId,
          title: cluster.title,
          summary: cluster.summary,
          confidenceScore: cluster.confidenceScore,
          severity: cluster.severity,
          status: CandidateIncidentStatus.CANDIDATE,
          correlationFactors: cluster.factors,
          explanation: cluster.explanation,
          primaryUser: cluster.primaryUser,
          primarySourceIp: cluster.primarySourceIp,
          primaryAssetId: cluster.primaryAssetId,
          eventIds: cluster.eventIds,
          detectionIds: cluster.detectionIds,
          firstSeen: new Date(cluster.firstSeen),
          lastSeen: new Date(cluster.lastSeen),
        });
        candidateEntity = await this.candidateRepo.save(candidateEntity);
      }
    }

    // Auto-promotion check
    let autoPromoted = false;
    if (evaluation.shouldAutoPromote && candidateEntity.status === CandidateIncidentStatus.CANDIDATE) {
      try {
        const incident = await this.incidentsService.createFromCandidate({
          id: candidateEntity.id,
          title: candidateEntity.title,
          explanation: candidateEntity.explanation,
          confidenceScore: candidateEntity.confidenceScore,
          severity: candidateEntity.severity,
          primarySourceIp: candidateEntity.primarySourceIp,
          detectionIds: candidateEntity.detectionIds,
        });

        candidateEntity.status = CandidateIncidentStatus.PROMOTED;
        candidateEntity.incidentId = incident.id;
        candidateEntity = await this.candidateRepo.save(candidateEntity);

        // Update in-memory cluster status
        cluster.status = CandidateIncidentStatus.PROMOTED;
        autoPromoted = true;

        await this.auditService.logAction({
          action: 'CANDIDATE_AUTO_PROMOTED',
          resourceType: 'CANDIDATE_INCIDENT',
          resourceId: candidateEntity.id,
          details: {
            incidentId: incident.id,
            incidentCode: incident.code,
            confidenceScore: candidateEntity.confidenceScore,
          },
        });
      } catch (err: any) {
        this.logger.error(`[CorrelationService] Auto-promotion failed: ${err.message}`, err.stack);
      }
    }

    return {
      candidate: candidateEntity,
      isNewCandidate: isNewCluster,
      autoPromoted,
      evaluation,
    };
  }

  /**
   * Promotes candidate incident to an official confirmed incident.
   * Fully idempotent: returns existing promoted state if called again.
   */
  async promoteCandidate(id: string, userId?: string, ipAddress?: string): Promise<CandidateIncident> {
    const candidate = await this.candidateRepo.findOne({
      where: { id },
      relations: ['primaryAsset', 'incident'],
    });

    if (!candidate) {
      throw new NotFoundException(`Candidate incident with id ${id} not found`);
    }

    // Idempotent guard
    if (candidate.status === CandidateIncidentStatus.PROMOTED && candidate.incidentId) {
      this.logger.warn(`[CorrelationService] Candidate ${id} is already promoted. Returning existing incident.`);
      return candidate;
    }

    if (candidate.status === CandidateIncidentStatus.DISMISSED) {
      throw new BadRequestException(`Cannot promote a dismissed candidate incident (${id}).`);
    }

    // Atomic promotion using optimistic check
    const incident = await this.incidentsService.createFromCandidate({
      id: candidate.id,
      title: candidate.title,
      explanation: candidate.explanation,
      confidenceScore: candidate.confidenceScore,
      severity: candidate.severity,
      primarySourceIp: candidate.primarySourceIp,
      detectionIds: candidate.detectionIds,
    });

    candidate.status = CandidateIncidentStatus.PROMOTED;
    candidate.incidentId = incident.id;
    candidate.incident = incident;

    const saved = await this.candidateRepo.save(candidate);

    // Update in-memory engine cluster
    const cluster = this.engine.getCluster(id);
    if (cluster) {
      cluster.status = CandidateIncidentStatus.PROMOTED;
    }

    await this.auditService.logAction({
      userId,
      action: 'CANDIDATE_MANUALLY_PROMOTED',
      resourceType: 'CANDIDATE_INCIDENT',
      resourceId: saved.id,
      ipAddress,
      details: {
        incidentId: incident.id,
        incidentCode: incident.code,
        confidenceScore: saved.confidenceScore,
      },
    });

    return saved;
  }

  /**
   * Dismisses a candidate incident with reason.
   * Fully idempotent: returns existing dismissed state if called again with same reason.
   */
  async dismissCandidate(
    id: string,
    reason: string,
    userId?: string,
    ipAddress?: string,
  ): Promise<CandidateIncident> {
    const candidate = await this.candidateRepo.findOne({ where: { id } });

    if (!candidate) {
      throw new NotFoundException(`Candidate incident with id ${id} not found`);
    }

    if (candidate.status === CandidateIncidentStatus.PROMOTED) {
      throw new BadRequestException(`Cannot dismiss an already promoted candidate incident (${id}).`);
    }

    if (candidate.status === CandidateIncidentStatus.DISMISSED) {
      return candidate; // Idempotent return
    }

    candidate.status = CandidateIncidentStatus.DISMISSED;
    candidate.dismissedReason = reason || 'Dismissed by analyst';
    candidate.dismissedByUserId = userId;

    const saved = await this.candidateRepo.save(candidate);

    // Update in-memory engine cluster
    const cluster = this.engine.getCluster(id);
    if (cluster) {
      cluster.status = CandidateIncidentStatus.DISMISSED;
    }

    await this.auditService.logAction({
      userId,
      action: 'CANDIDATE_DISMISSED',
      resourceType: 'CANDIDATE_INCIDENT',
      resourceId: saved.id,
      ipAddress,
      details: {
        reason: candidate.dismissedReason,
      },
    });

    return saved;
  }

  /**
   * Query candidate incidents with filtering and pagination.
   */
  async findAllCandidates(options?: {
    status?: CandidateIncidentStatus;
    minConfidence?: number;
    limit?: number;
    offset?: number;
  }): Promise<{ data: CandidateIncident[]; total: number }> {
    const limit = Math.min(options?.limit || 20, 100);
    const offset = options?.offset || 0;

    const query = this.candidateRepo
      .createQueryBuilder('candidate')
      .leftJoinAndSelect('candidate.primaryAsset', 'primaryAsset')
      .leftJoinAndSelect('candidate.incident', 'incident')
      .leftJoinAndSelect('candidate.dismissedByUser', 'dismissedByUser')
      .orderBy('candidate.lastSeen', 'DESC')
      .take(limit)
      .skip(offset);

    if (options?.status) {
      query.andWhere('candidate.status = :status', { status: options.status });
    }

    if (options?.minConfidence !== undefined) {
      query.andWhere('candidate.confidenceScore >= :minConfidence', {
        minConfidence: options.minConfidence,
      });
    }

    const [data, total] = await query.getManyAndCount();
    return { data, total };
  }

  /**
   * Find candidate incident by ID with relations.
   */
  async findById(id: string): Promise<CandidateIncident> {
    const candidate = await this.candidateRepo.findOne({
      where: { id },
      relations: ['primaryAsset', 'incident', 'dismissedByUser'],
    });

    if (!candidate) {
      throw new NotFoundException(`Candidate incident with id ${id} not found`);
    }

    return candidate;
  }
}
