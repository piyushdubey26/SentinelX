import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SecurityEvent, EventSeverity } from './entities/security-event.entity';
import { IngestEventDto } from './dto/ingest-event.dto';
import { DetectionsService } from '../detections/detections.service';

@Injectable()
export class EventsService {
  constructor(
    @InjectRepository(SecurityEvent)
    private readonly eventRepo: Repository<SecurityEvent>,
    private readonly detectionsService: DetectionsService,
  ) {}

  async ingest(dto: IngestEventDto, clientIp?: string): Promise<{
    event: SecurityEvent;
    detectionCreated: boolean;
    incidentCreated: boolean;
  }> {
    const eventTimestamp = dto.eventTimestamp ? new Date(dto.eventTimestamp) : new Date();

    const normalizedDetails = {
      normalizedSourceIp: dto.sourceIp,
      normalizedTargetUser: dto.targetUser ? dto.targetUser.toLowerCase().trim() : undefined,
      ingestedFromIp: clientIp,
      protocol: 'HTTPS',
    };

    const event = this.eventRepo.create({
      eventType: dto.eventType,
      severity: dto.severity || EventSeverity.INFO,
      sourceIp: dto.sourceIp,
      sourcePort: dto.sourcePort,
      destinationIp: dto.destinationIp,
      targetUser: dto.targetUser,
      rawPayload: dto.rawPayload || {},
      normalizedDetails,
      eventTimestamp,
    });

    const savedEvent = await this.eventRepo.save(event);

    // Evaluate detection rules
    const detectionResult = await this.detectionsService.processEvent(savedEvent);

    return {
      event: savedEvent,
      detectionCreated: !!detectionResult.detection,
      incidentCreated: detectionResult.incidentCreated,
    };
  }

  async findAll(limit: number = 50, offset: number = 0): Promise<{ data: SecurityEvent[]; total: number }> {
    const [data, total] = await this.eventRepo.findAndCount({
      order: { eventTimestamp: 'DESC' },
      take: Math.min(limit, 100),
      skip: offset,
      relations: ['asset'],
    });
    return { data, total };
  }
}
