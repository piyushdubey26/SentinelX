import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CandidateIncident } from './entities/candidate-incident.entity';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { CorrelationService } from './correlation.service';
import { CorrelationController } from './correlation.controller';
import { IncidentsModule } from '../incidents/incidents.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([CandidateIncident, SecurityEvent]),
    IncidentsModule,
    AuditModule,
  ],
  controllers: [CorrelationController],
  providers: [CorrelationService],
  exports: [CorrelationService],
})
export class CorrelationModule {}
