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
import { Detection } from '../../detections/entities/detection.entity';
import { User } from '../../users/entities/user.entity';

export enum IncidentStatus {
  OPEN = 'OPEN',
  INVESTIGATING = 'INVESTIGATING',
  CONTAINED = 'CONTAINED',
  RESOLVED = 'RESOLVED',
  CLOSED = 'CLOSED',
}

@Entity({ name: 'incidents' })
@Index('idx_incidents_status_severity', ['status', 'severity'])
@Index('idx_incidents_created_at', ['createdAt'])
export class Incident {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 50, unique: true })
  code!: string;

  @Column({ type: 'varchar', length: 255 })
  title!: string;

  @Column({ type: 'text' })
  summary!: string;

  @Column({
    type: 'enum',
    enum: EventSeverity,
    default: EventSeverity.MEDIUM,
  })
  severity!: EventSeverity;

  @Column({
    type: 'enum',
    enum: IncidentStatus,
    default: IncidentStatus.OPEN,
  })
  status!: IncidentStatus;

  @Column({ type: 'varchar', length: 45, nullable: true, name: 'source_ip' })
  sourceIp?: string;

  @Column({ type: 'uuid', nullable: true, name: 'detection_id' })
  detectionId?: string;

  @ManyToOne(() => Detection, { nullable: true, onDelete: 'SET NULL', eager: true })
  @JoinColumn({ name: 'detection_id' })
  detection?: Detection;

  @Column({ type: 'uuid', nullable: true, name: 'assigned_to_user_id' })
  assignedToUserId?: string;

  @ManyToOne(() => User, { nullable: true, onDelete: 'SET NULL', eager: true })
  @JoinColumn({ name: 'assigned_to_user_id' })
  assignedTo?: User;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
