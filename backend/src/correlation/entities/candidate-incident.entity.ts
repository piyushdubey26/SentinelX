import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { EventSeverity } from '../../events/entities/security-event.entity';
import { Asset } from '../../assets/entities/asset.entity';
import { Incident } from '../../incidents/entities/incident.entity';
import { User } from '../../users/entities/user.entity';
import { CandidateIncidentStatus, CorrelationFactor } from '../correlation.types';

@Entity({ name: 'candidate_incidents' })
@Index('idx_candidates_status_last_seen', ['status', 'lastSeen'])
@Index('idx_candidates_primary_user', ['primaryUser'])
@Index('idx_candidates_primary_ip', ['primarySourceIp'])
@Index('idx_candidates_incident_id', ['incidentId'])
@Index('idx_candidates_confidence', ['confidenceScore'])
export class CandidateIncident {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 255 })
  title!: string;

  @Column({ type: 'text' })
  summary!: string;

  @Column({
    type: 'numeric',
    precision: 4,
    scale: 3,
    name: 'confidence_score',
    transformer: {
      to: (value: number) => value,
      from: (value: string | number) => parseFloat(value as string),
    },
  })
  confidenceScore!: number;

  @Column({
    type: 'enum',
    enum: EventSeverity,
    default: EventSeverity.MEDIUM,
  })
  severity!: EventSeverity;

  @Column({
    type: 'varchar',
    length: 50,
    default: CandidateIncidentStatus.CANDIDATE,
  })
  status!: CandidateIncidentStatus;

  @Column({ type: 'jsonb', name: 'correlation_factors', default: () => "'[]'" })
  correlationFactors!: CorrelationFactor[];

  @Column({ type: 'text' })
  explanation!: string;

  @Column({ type: 'varchar', length: 100, nullable: true, name: 'primary_user' })
  primaryUser?: string;

  @Column({ type: 'varchar', length: 45, nullable: true, name: 'primary_source_ip' })
  primarySourceIp?: string;

  @Column({ type: 'uuid', nullable: true, name: 'primary_asset_id' })
  primaryAssetId?: string;

  @ManyToOne(() => Asset, { nullable: true, onDelete: 'SET NULL', eager: true })
  @JoinColumn({ name: 'primary_asset_id' })
  primaryAsset?: Asset;

  @Column({ type: 'uuid', array: true, default: () => "'{}'", name: 'event_ids' })
  eventIds!: string[];

  @Column({ type: 'uuid', array: true, default: () => "'{}'", name: 'detection_ids' })
  detectionIds!: string[];

  @Column({ type: 'uuid', nullable: true, name: 'incident_id' })
  incidentId?: string;

  @ManyToOne(() => Incident, { nullable: true, onDelete: 'SET NULL', eager: true })
  @JoinColumn({ name: 'incident_id' })
  incident?: Incident;

  @Column({ type: 'text', nullable: true, name: 'dismissed_reason' })
  dismissedReason?: string;

  @Column({ type: 'uuid', nullable: true, name: 'dismissed_by_user_id' })
  dismissedByUserId?: string;

  @ManyToOne(() => User, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'dismissed_by_user_id' })
  dismissedByUser?: User;

  @Column({ type: 'timestamptz', name: 'first_seen' })
  firstSeen!: Date;

  @Column({ type: 'timestamptz', name: 'last_seen' })
  lastSeen!: Date;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
