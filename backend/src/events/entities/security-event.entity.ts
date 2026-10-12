import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Asset } from '../../assets/entities/asset.entity';

export enum EventSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

@Entity({ name: 'security_events' })
@Index('idx_events_correlation', ['eventType', 'sourceIp', 'eventTimestamp'])
@Index('idx_events_timestamp', ['eventTimestamp'])
export class SecurityEvent {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar', length: 100, name: 'event_type' })
  eventType!: string;

  @Column({
    type: 'enum',
    enum: EventSeverity,
    default: EventSeverity.INFO,
  })
  severity!: EventSeverity;

  @Index()
  @Column({ type: 'varchar', length: 45, name: 'source_ip' })
  sourceIp!: string;

  @Column({ type: 'int', nullable: true, name: 'source_port' })
  sourcePort?: number;

  @Column({ type: 'varchar', length: 45, nullable: true, name: 'destination_ip' })
  destinationIp?: string;

  @Index()
  @Column({ type: 'varchar', length: 100, nullable: true, name: 'target_user' })
  targetUser?: string;

  @Column({ type: 'uuid', nullable: true, name: 'asset_id' })
  assetId?: string;

  @ManyToOne(() => Asset, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'asset_id' })
  asset?: Asset;

  @Column({ type: 'jsonb', name: 'raw_payload', default: {} })
  rawPayload!: Record<string, any>;

  @Column({ type: 'jsonb', name: 'normalized_details', default: {} })
  normalizedDetails!: Record<string, any>;

  @Column({ type: 'timestamptz', name: 'event_timestamp' })
  eventTimestamp!: Date;

  @CreateDateColumn({ type: 'timestamptz', name: 'ingested_at' })
  ingestedAt!: Date;
}
