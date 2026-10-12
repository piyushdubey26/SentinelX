import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SecurityEvent } from './entities/security-event.entity';
import { IngestEventDto } from './dto/ingest-event.dto';
import { StreamingService } from '../streaming/streaming.service';

@Injectable()
export class EventsService {
  constructor(
    @InjectRepository(SecurityEvent)
    private readonly eventRepo: Repository<SecurityEvent>,
    private readonly streamingService: StreamingService,
  ) {}

  async ingest(
    dto: IngestEventDto,
    clientIp?: string,
    sync: boolean = true,
  ): Promise<{
    event?: SecurityEvent;
    detectionCreated: boolean;
    incidentCreated: boolean;
    candidateCreated?: boolean;
    candidateId?: string;
    trackingId?: string;
    idempotencyKey?: string;
    status?: string;
  }> {
    const streamResult = await this.streamingService.ingestEvent(dto, clientIp, sync);

    return {
      event: streamResult.event,
      detectionCreated: !!streamResult.detectionCreated,
      incidentCreated: !!streamResult.incidentCreated,
      candidateCreated: streamResult.candidateCreated,
      candidateId: streamResult.candidateId,
      trackingId: streamResult.trackingId,
      idempotencyKey: streamResult.idempotencyKey,
      status: streamResult.status,
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
