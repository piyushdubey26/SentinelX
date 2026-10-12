import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Detection } from './entities/detection.entity';
import { DetectionsService } from './detections.service';
import { DetectionsController } from './detections.controller';
import { IncidentsModule } from '../incidents/incidents.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [TypeOrmModule.forFeature([Detection]), IncidentsModule, AuditModule],
  controllers: [DetectionsController],
  providers: [DetectionsService],
  exports: [DetectionsService],
})
export class DetectionsModule {}
