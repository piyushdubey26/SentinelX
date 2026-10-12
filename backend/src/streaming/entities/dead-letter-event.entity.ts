import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('dead_letter_events')
export class DeadLetterEvent {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 100 })
  topic!: string;

  @Column({ type: 'text', name: 'error_message' })
  errorMessage!: string;

  @Column({ type: 'text', nullable: true, name: 'error_stack' })
  errorStack?: string;

  @Column({ type: 'int', default: 0, name: 'retry_count' })
  retryCount!: number;

  @Column({ type: 'jsonb', default: {}, name: 'raw_payload' })
  rawPayload!: Record<string, any>;

  @CreateDateColumn({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP', name: 'failed_at' })
  failedAt!: Date;

  @Column({ type: 'boolean', default: false })
  resolved!: boolean;
}
