import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { EventSeverity } from '../../events/entities/security-event.entity';

@Entity({ name: 'detections' })
@Index('idx_detections_source_rule', ['sourceIp', 'ruleId'])
export class Detection {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'varchar', length: 100, name: 'rule_id' })
  ruleId!: string;

  @Column({ type: 'varchar', length: 255, name: 'rule_name' })
  ruleName!: string;

  @Column({
    type: 'enum',
    enum: EventSeverity,
    default: EventSeverity.HIGH,
  })
  severity!: EventSeverity;

  @Index()
  @Column({ type: 'varchar', length: 45, name: 'source_ip' })
  sourceIp!: string;

  @Column({ type: 'varchar', length: 100, nullable: true, name: 'target_user' })
  targetUser?: string;

  @Column({ type: 'int', name: 'trigger_count' })
  triggerCount!: number;

  @Column({ type: 'int', name: 'time_window_seconds' })
  timeWindowSeconds!: number;

  @Column({ type: 'jsonb', default: {} })
  evidence!: Record<string, any>;

  @CreateDateColumn({ type: 'timestamptz', name: 'detected_at' })
  detectedAt!: Date;
}
