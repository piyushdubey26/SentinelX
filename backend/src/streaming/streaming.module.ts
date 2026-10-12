import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { IdempotencyKey } from './entities/idempotency-key.entity';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { EventNormalizerService } from './event-normalizer.service';
import { IdempotencyService } from './idempotency.service';
import { DeadLetterQueueService } from './dead-letter-queue.service';
import { EmbeddedStreamingDriver } from './drivers/embedded-streaming.driver';
import { KafkaStreamingDriver } from './drivers/kafka-streaming.driver';
import { StreamingService } from './streaming.service';
import { DetectionsModule } from '../detections/detections.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([IdempotencyKey, DeadLetterEvent, SecurityEvent]),
    forwardRef(() => DetectionsModule),
  ],
  providers: [
    EventNormalizerService,
    IdempotencyService,
    DeadLetterQueueService,
    EmbeddedStreamingDriver,
    KafkaStreamingDriver,
    StreamingService,
  ],
  exports: [
    StreamingService,
    DeadLetterQueueService,
    EventNormalizerService,
    IdempotencyService,
  ],
})
export class StreamingModule {}
