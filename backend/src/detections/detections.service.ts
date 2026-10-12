import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Detection } from './entities/detection.entity';
import { SecurityEvent, EventSeverity } from '../events/entities/security-event.entity';
import { SlidingWindowDetector } from './dsa/sliding-window-detector';
import { IncidentsService } from '../incidents/incidents.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class DetectionsService {
  private readonly bruteForceDetector: SlidingWindowDetector;

  constructor(
    @InjectRepository(Detection)
    private readonly detectionRepo: Repository<Detection>,
    private readonly incidentsService: IncidentsService,
    private readonly auditService: AuditService,
  ) {
    // Brute force rule: 5 failed logins within 60 seconds
    this.bruteForceDetector = new SlidingWindowDetector(
      'RULE-BRUTE-FORCE-001',
      'Suspicious Privileged Activity / Brute Force',
      5,
      60,
    );
  }

  async processEvent(event: SecurityEvent): Promise<{ detection?: Detection; incidentCreated: boolean }> {
    // Only evaluate authentication failure events
    if (event.eventType !== 'AUTH_FAILURE') {
      return { incidentCreated: false };
    }

    const sourceKey = `${event.sourceIp}:${event.targetUser || 'global'}`;
    const timestampMs = new Date(event.eventTimestamp).getTime();

    const evaluation = this.bruteForceDetector.recordAndEvaluate(
      event.id,
      sourceKey,
      timestampMs,
    );

    if (evaluation.triggered) {
      // 1. Create Detection Entity
      const detection = this.detectionRepo.create({
        ruleId: evaluation.ruleId,
        ruleName: evaluation.ruleName,
        severity: EventSeverity.CRITICAL,
        sourceIp: event.sourceIp,
        targetUser: event.targetUser,
        triggerCount: evaluation.eventCount,
        timeWindowSeconds: evaluation.timeWindowSeconds,
        evidence: {
          triggerEventIds: evaluation.triggerEventIds,
          sourceKey,
          timestamp: new Date().toISOString(),
        },
      });

      const savedDetection = await this.detectionRepo.save(detection);

      // 2. Automatically generate an Incident for SOC analysts
      await this.incidentsService.createFromDetection(savedDetection);

      // 3. Log audit trail
      await this.auditService.logAction({
        action: 'DETECTION_TRIGGERED',
        resourceType: 'DETECTION',
        resourceId: savedDetection.id,
        details: {
          ruleId: savedDetection.ruleId,
          sourceIp: savedDetection.sourceIp,
          count: savedDetection.triggerCount,
        },
      });

      // Reset detector key to avoid infinite cascade for same window
      this.bruteForceDetector.resetKey(sourceKey);

      return { detection: savedDetection, incidentCreated: true };
    }

    return { incidentCreated: false };
  }

  async findAll(limit: number = 20, offset: number = 0): Promise<{ data: Detection[]; total: number }> {
    const [data, total] = await this.detectionRepo.findAndCount({
      order: { detectedAt: 'DESC' },
      take: Math.min(limit, 100),
      skip: offset,
    });
    return { data, total };
  }
}
