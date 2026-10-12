import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';

@Injectable()
export class DeadLetterQueueService {
  private readonly logger = new Logger(DeadLetterQueueService.name);

  constructor(
    @InjectRepository(DeadLetterEvent)
    private readonly dlqRepo: Repository<DeadLetterEvent>,
  ) {}

  /**
   * Records a failed message to the Dead Letter Queue store.
   */
  async captureFailure(
    topic: string,
    rawPayload: Record<string, any>,
    error: Error,
    retryCount: number = 0,
  ): Promise<DeadLetterEvent> {
    this.logger.warn(
      `[DLQ] Routing failed message from topic ${topic} to Dead Letter Queue: ${error.message}`,
    );

    const record = this.dlqRepo.create({
      topic,
      rawPayload,
      errorMessage: error.message || 'Unknown processing error',
      errorStack: error.stack,
      retryCount,
      failedAt: new Date(),
      resolved: false,
    });

    return this.dlqRepo.save(record);
  }

  async findAll(
    limit: number = 50,
    offset: number = 0,
    resolved?: boolean,
  ): Promise<{ data: DeadLetterEvent[]; total: number }> {
    const where: any = {};
    if (resolved !== undefined) {
      where.resolved = resolved;
    }

    const [data, total] = await this.dlqRepo.findAndCount({
      where,
      order: { failedAt: 'DESC' },
      take: Math.min(limit, 100),
      skip: offset,
    });

    return { data, total };
  }

  async markResolved(id: string): Promise<DeadLetterEvent | null> {
    const item = await this.dlqRepo.findOne({ where: { id } });
    if (!item) return null;
    item.resolved = true;
    return this.dlqRepo.save(item);
  }
}
