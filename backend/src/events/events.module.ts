import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecurityEvent } from './entities/security-event.entity';
import { EventsService } from './events.service';
import { EventsController } from './events.controller';
import { DetectionsModule } from '../detections/detections.module';
import { StreamingModule } from '../streaming/streaming.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([SecurityEvent]),
    DetectionsModule,
    StreamingModule,
  ],
  controllers: [EventsController],
  providers: [EventsService],
  exports: [EventsService],
})
export class EventsModule {}
