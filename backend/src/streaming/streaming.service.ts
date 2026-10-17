import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { StreamingDriver } from './drivers/streaming-driver.interface';
import { EmbeddedStreamingDriver } from './drivers/embedded-streaming.driver';
import { KafkaStreamingDriver } from './drivers/kafka-streaming.driver';
import { EventNormalizerService } from './event-normalizer.service';
import { IdempotencyService } from './idempotency.service';
import { DeadLetterQueueService } from './dead-letter-queue.service';
import { SecurityEventEnvelope, StreamMessage, StreamingStats } from './streaming.types';
import { IngestEventDto } from '../events/dto/ingest-event.dto';
import { SecurityEvent, EventSeverity } from '../events/entities/security-event.entity';
import { DetectionsService } from '../detections/detections.service';
import { CorrelationService } from '../correlation/correlation.service';

export const RAW_EVENTS_TOPIC = 'security.events.raw';
export const DLQ_TOPIC = 'security.events.dlq';
export const SOC_CONSUMER_GROUP = 'sentinelx-soc-group';

@Injectable()
export class StreamingService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(StreamingService.name);
  private driver!: StreamingDriver;

  private totalPublished = 0;
  private totalConsumed = 0;
  private totalRetried = 0;
  private totalDeadLettered = 0;

  // Transient listeners for synchronous completion (e.g., tests or ?sync=true)
  private readonly eventWaiters = new Map<
    string,
    (res: {
      event: SecurityEvent;
      detectionCreated: boolean;
      incidentCreated: boolean;
      candidateCreated?: boolean;
      candidateId?: string;
    }) => void
  >();

  constructor(
    private readonly normalizer: EventNormalizerService,
    private readonly idempotency: IdempotencyService,
    private readonly dlq: DeadLetterQueueService,
    private readonly embeddedDriver: EmbeddedStreamingDriver,
    private readonly kafkaDriver: KafkaStreamingDriver,
    @InjectRepository(SecurityEvent)
    private readonly eventRepo: Repository<SecurityEvent>,
    private readonly detectionsService: DetectionsService,
    private readonly correlationService: CorrelationService,
  ) {}

  async onModuleInit() {
    // Select active driver based on environment
    if (process.env.KAFKA_BROKERS) {
      try {
        await this.kafkaDriver.connect();
        this.driver = this.kafkaDriver;
        this.logger.log('[StreamingService] Operating in Kafka Broker Mode.');
      } catch {
        this.logger.warn('[StreamingService] Kafka connection failed; falling back to Embedded Driver.');
        await this.embeddedDriver.connect();
        this.driver = this.embeddedDriver;
      }
    } else {
      await this.embeddedDriver.connect();
      this.driver = this.embeddedDriver;
      this.logger.log('[StreamingService] Operating in Embedded In-Memory Driver Mode.');
    }

    // Start consumer subscription
    await this.driver.subscribe(RAW_EVENTS_TOPIC, SOC_CONSUMER_GROUP, async (msg) => {
      await this.handleIncomingMessage(msg);
    });
  }

  async onModuleDestroy() {
    if (this.driver) {
      await this.driver.disconnect();
    }
  }

  /**
   * Publishes an incoming raw event to the streaming broker.
   */
  async ingestEvent(
    dto: IngestEventDto,
    clientIp?: string,
    waitForSync: boolean = false,
  ): Promise<{
    trackingId: string;
    idempotencyKey: string;
    status: 'QUEUED' | 'PROCESSED';
    event?: SecurityEvent;
    detectionCreated?: boolean;
    incidentCreated?: boolean;
    candidateCreated?: boolean;
    candidateId?: string;
  }> {
    const envelope = this.normalizer.normalize(dto, clientIp);

    // Setup sync promise if requested
    let syncPromise: Promise<{
      event: SecurityEvent;
      detectionCreated: boolean;
      incidentCreated: boolean;
      candidateCreated?: boolean;
      candidateId?: string;
    }> | null = null;

    if (waitForSync) {
      syncPromise = new Promise((resolve) => {
        this.eventWaiters.set(envelope.envelopeId, resolve);
      });
    }

    const message: StreamMessage<SecurityEventEnvelope> = {
      topic: RAW_EVENTS_TOPIC,
      key: envelope.idempotencyKey,
      value: envelope,
    };

    await this.driver.publish(RAW_EVENTS_TOPIC, message);
    this.totalPublished++;

    if (waitForSync && syncPromise) {
      let timeoutHandle: NodeJS.Timeout | null = null;
      const syncTimeoutMs = process.env.NODE_ENV === 'test' ? 10000 : 5000;
      const timeoutPromise = new Promise<null>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error('Streaming sync processing timed out')), syncTimeoutMs);
        timeoutHandle.unref();
      });

      try {
        const syncResult = await Promise.race([syncPromise, timeoutPromise]);
        if (timeoutHandle) clearTimeout(timeoutHandle);

        if (syncResult) {
          return {
            trackingId: envelope.envelopeId,
            idempotencyKey: envelope.idempotencyKey,
            status: 'PROCESSED',
            event: syncResult.event,
            detectionCreated: syncResult.detectionCreated,
            incidentCreated: syncResult.incidentCreated,
            candidateCreated: syncResult.candidateCreated,
            candidateId: syncResult.candidateId,
          };
        }
      } catch (err) {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        throw err;
      }
    }

    return {
      trackingId: envelope.envelopeId,
      idempotencyKey: envelope.idempotencyKey,
      status: 'QUEUED',
    };
  }

  /**
   * Core Consumer Logic with Idempotency, Exponential Backoff Retries & DLQ Routing
   */
  private async handleIncomingMessage(msg: StreamMessage<SecurityEventEnvelope>): Promise<void> {
    const envelope = msg.value;
    if (!envelope || !envelope.idempotencyKey) {
      await this.dlq.captureFailure(
        msg.topic,
        msg.value || {},
        new Error('Invalid envelope structure: missing idempotencyKey'),
      );
      this.totalDeadLettered++;
      return;
    }

    // 1. Idempotency Check (Guarantee Exactly-Once processing)
    const claimed = await this.idempotency.checkAndClaim(envelope.idempotencyKey);
    if (!claimed) {
      this.logger.debug(
        `[StreamingService] Duplicate message detected (key: ${envelope.idempotencyKey}). Skipping processing.`,
      );
      return;
    }

    // 2. Retry loop with exponential backoff (up to 3 attempts)
    const MAX_RETRIES = 3;
    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt < MAX_RETRIES) {
      attempt++;
      try {
        await this.processEnvelope(envelope);
        this.totalConsumed++;
        return; // Success!
      } catch (err: any) {
        lastError = err;
        this.totalRetried++;
        this.logger.warn(
          `[StreamingService] Processing attempt ${attempt}/${MAX_RETRIES} failed for envelope ${envelope.envelopeId}: ${err.message}`,
        );

        if (attempt < MAX_RETRIES) {
          // Exponential backoff: 50ms, 150ms
          const backoffMs = attempt * 50 + Math.floor(Math.random() * 20);
          await new Promise((resolve) => setTimeout(resolve, backoffMs));
        }
      }
    }

    // 3. Exhausted retries -> Route to Dead Letter Queue
    this.totalDeadLettered++;
    await this.dlq.captureFailure(
      msg.topic,
      envelope,
      lastError || new Error('Max processing retries exhausted'),
      attempt,
    );

    const waiter = this.eventWaiters.get(envelope.envelopeId);
    if (waiter) {
      this.eventWaiters.delete(envelope.envelopeId);
    }

    // Also publish dead letter event to DLQ topic for external stream consumers
    await this.driver.publish(DLQ_TOPIC, {
      topic: DLQ_TOPIC,
      key: envelope.idempotencyKey,
      value: {
        envelope,
        error: lastError?.message,
        retryCount: attempt,
      },
    });
  }

  /**
   * Transforms envelope to database entity and runs detection
   */
  private async processEnvelope(envelope: SecurityEventEnvelope): Promise<void> {
    // Validate required fields
    if (!envelope.event || !envelope.event.type || !envelope.source || !envelope.source.ip) {
      throw new Error('Poison pill: event payload missing mandatory type or source IP');
    }

    const event = this.eventRepo.create({
      eventType: envelope.event.type,
      severity: envelope.event.severity || EventSeverity.INFO,
      sourceIp: envelope.source.ip,
      sourcePort: envelope.source.port,
      destinationIp: envelope.destination?.ip,
      targetUser: envelope.user?.name,
      rawPayload: envelope.rawPayload || {},
      normalizedDetails: envelope.normalizedDetails || {},
      eventTimestamp: new Date(envelope.event.timestamp),
    });

    const savedEvent = await this.eventRepo.save(event);

    // Evaluate detection
    const detectionResult = await this.detectionsService.processEvent(savedEvent);

    // Evaluate multi-attribute correlation
    const correlationResult = await this.correlationService.processEvent(
      savedEvent,
      detectionResult.detection,
    );

    // Notify any synchronous waiters
    const waiter = this.eventWaiters.get(envelope.envelopeId);
    if (waiter) {
      this.eventWaiters.delete(envelope.envelopeId);
      waiter({
        event: savedEvent,
        detectionCreated: !!detectionResult.detection,
        incidentCreated: detectionResult.incidentCreated || correlationResult.autoPromoted,
        candidateCreated: correlationResult.isNewCandidate,
        candidateId: correlationResult.candidate.id,
      });
    }
  }

  /**
   * Diagnostics and Consumer Health metrics
   */
  async getStats(): Promise<StreamingStats> {
    const lag = await this.driver.getLag(RAW_EVENTS_TOPIC);
    return {
      driver: this.driver.name,
      status: this.driver.getStatus(),
      topics: [RAW_EVENTS_TOPIC, DLQ_TOPIC],
      totalPublished: this.totalPublished,
      totalConsumed: this.totalConsumed,
      totalRetried: this.totalRetried,
      totalDeadLettered: this.totalDeadLettered,
      lag,
    };
  }
}
