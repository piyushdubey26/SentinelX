import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecurityEvent } from './entities/security-event.entity';
import { EventsService } from './events.service';
import { EventsController } from './events.controller';
import { DetectionsModule } from '../detections/detections.module';

@Module({
  imports: [TypeOrmModule.forFeature([SecurityEvent]), DetectionsModule],
  controllers: [EventsController],
  providers: [EventsService],
  exports: [EventsService],
})
export class EventsModule {}
