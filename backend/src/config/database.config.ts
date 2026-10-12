import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { Role } from '../users/entities/role.entity';
import { User } from '../users/entities/user.entity';
import { Asset } from '../assets/entities/asset.entity';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { Detection } from '../detections/entities/detection.entity';
import { Incident } from '../incidents/entities/incident.entity';
import { AuditLog } from '../audit/entities/audit-log.entity';
import { IdempotencyKey } from '../streaming/entities/idempotency-key.entity';
import { DeadLetterEvent } from '../streaming/entities/dead-letter-event.entity';
import { CandidateIncident } from '../correlation/entities/candidate-incident.entity';

export const ALL_ENTITIES = [
  Role,
  User,
  Asset,
  SecurityEvent,
  Detection,
  Incident,
  AuditLog,
  IdempotencyKey,
  DeadLetterEvent,
  CandidateIncident,
];

export const databaseConfig = registerAs(
  'database',
  (): TypeOrmModuleOptions => ({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'piyushdubey',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'sentinelx',
    entities: ALL_ENTITIES,
    synchronize: false,
    logging: process.env.DB_LOGGING === 'true',
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  }),
);
