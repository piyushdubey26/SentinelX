import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Incident } from '../incidents/entities/incident.entity';
import { Asset } from '../assets/entities/asset.entity';
import { CandidateIncident } from '../correlation/entities/candidate-incident.entity';
import { Detection } from '../detections/entities/detection.entity';
import { AuditModule } from '../audit/audit.module';
import { RiskScoringService } from './risk-scoring.service';
import { RiskController } from './risk.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([Incident, Asset, CandidateIncident, Detection]),
    AuditModule,
  ],
  providers: [RiskScoringService],
  controllers: [RiskController],
  exports: [RiskScoringService],
})
export class RiskModule {}
