import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Incident, IncidentStatus } from './entities/incident.entity';
import { Detection } from '../detections/entities/detection.entity';
import { AuditService } from '../audit/audit.service';
import { EventSeverity } from '../events/entities/security-event.entity';

@Injectable()
export class IncidentsService {
  constructor(
    @InjectRepository(Incident)
    private readonly incidentRepo: Repository<Incident>,
    private readonly auditService: AuditService,
  ) {}

  private async generateNextCode(): Promise<string> {
    const count = await this.incidentRepo.count();
    const sequence = 2048 + count;
    return `INC-${sequence}`;
  }

  async createFromDetection(detection: Detection): Promise<Incident> {
    const code = await this.generateNextCode();
    const incident = this.incidentRepo.create({
      code,
      title: `${detection.ruleName} [${detection.sourceIp}]`,
      summary: `Automated detection triggered by ${detection.triggerCount} matching events within ${detection.timeWindowSeconds}s window.`,
      severity: detection.severity,
      status: IncidentStatus.OPEN,
      sourceIp: detection.sourceIp,
      detectionId: detection.id,
    });

    const saved = await this.incidentRepo.save(incident);

    await this.auditService.logAction({
      action: 'INCIDENT_CREATED',
      resourceType: 'INCIDENT',
      resourceId: saved.id,
      details: {
        code: saved.code,
        ruleId: detection.ruleId,
        sourceIp: detection.sourceIp,
        severity: saved.severity,
      },
    });

    return saved;
  }

  async createFromCandidate(candidate: {
    id: string;
    title: string;
    explanation: string;
    confidenceScore: number;
    severity: EventSeverity;
    primarySourceIp?: string;
    detectionIds?: string[];
  }): Promise<Incident> {
    const code = await this.generateNextCode();
    const incident = this.incidentRepo.create({
      code,
      title: `[CORRELATED] ${candidate.title}`,
      summary: `Correlated Incident promoted from candidate cluster ${candidate.id}. Confidence: ${candidate.confidenceScore}. ${candidate.explanation}`,
      severity: candidate.severity,
      status: IncidentStatus.OPEN,
      sourceIp: candidate.primarySourceIp,
      detectionId: candidate.detectionIds && candidate.detectionIds.length > 0 ? candidate.detectionIds[0] : undefined,
    });

    const saved = await this.incidentRepo.save(incident);

    await this.auditService.logAction({
      action: 'INCIDENT_PROMOTED_FROM_CANDIDATE',
      resourceType: 'INCIDENT',
      resourceId: saved.id,
      details: {
        code: saved.code,
        candidateId: candidate.id,
        confidenceScore: candidate.confidenceScore,
        severity: saved.severity,
      },
    });

    return saved;
  }

  async findAll(options?: {
    status?: IncidentStatus;
    severity?: EventSeverity;
    limit?: number;
    offset?: number;
  }): Promise<{ data: Incident[]; total: number }> {
    const limit = Math.min(options?.limit || 20, 100);
    const offset = options?.offset || 0;

    const query = this.incidentRepo.createQueryBuilder('incident')
      .leftJoinAndSelect('incident.detection', 'detection')
      .leftJoinAndSelect('incident.assignedTo', 'assignedTo')
      .orderBy('incident.createdAt', 'DESC')
      .take(limit)
      .skip(offset);

    if (options?.status) {
      query.andWhere('incident.status = :status', { status: options.status });
    }

    if (options?.severity) {
      query.andWhere('incident.severity = :severity', { severity: options.severity });
    }

    const [data, total] = await query.getManyAndCount();
    return { data, total };
  }

  async findById(id: string): Promise<Incident> {
    const incident = await this.incidentRepo.findOne({
      where: [{ id }, { code: id }],
      relations: ['detection', 'assignedTo'],
    });

    if (!incident) {
      throw new NotFoundException(`Incident with identifier ${id} not found`);
    }

    return incident;
  }

  async updateStatus(id: string, status: IncidentStatus, userId?: string, ipAddress?: string): Promise<Incident> {
    const incident = await this.findById(id);
    const previousStatus = incident.status;
    incident.status = status;
    const updated = await this.incidentRepo.save(incident);

    await this.auditService.logAction({
      userId,
      action: 'INCIDENT_STATUS_UPDATED',
      resourceType: 'INCIDENT',
      resourceId: incident.id,
      ipAddress,
      details: {
        code: incident.code,
        previousStatus,
        newStatus: status,
      },
    });

    return updated;
  }

  async getCounts(): Promise<{ criticalCount: number; openCount: number; totalCount: number }> {
    const criticalCount = await this.incidentRepo.count({
      where: { severity: EventSeverity.CRITICAL },
    });
    const openCount = await this.incidentRepo.count({
      where: [
        { status: IncidentStatus.OPEN },
        { status: IncidentStatus.INVESTIGATING },
      ],
    });
    const totalCount = await this.incidentRepo.count();

    return { criticalCount, openCount, totalCount };
  }
}
