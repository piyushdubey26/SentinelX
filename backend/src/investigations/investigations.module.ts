import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Incident } from '../incidents/entities/incident.entity';
import { CandidateIncident } from '../correlation/entities/candidate-incident.entity';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { Asset } from '../assets/entities/asset.entity';
import { Detection } from '../detections/entities/detection.entity';
import { User } from '../users/entities/user.entity';
import { AuditModule } from '../audit/audit.module';
import { InvestigationsController } from './investigations.controller';
import { InvestigationsService } from './investigations.service';
import { GraphBuilderService } from './graph-builder.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Incident,
      CandidateIncident,
      SecurityEvent,
      Asset,
      Detection,
      User,
    ]),
    AuditModule,
  ],
  controllers: [InvestigationsController],
  providers: [InvestigationsService, GraphBuilderService],
  exports: [InvestigationsService, GraphBuilderService],
})
export class InvestigationsModule {}
