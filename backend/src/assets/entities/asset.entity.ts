import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export enum AssetCriticality {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export enum AssetEnvironment {
  PRODUCTION = 'PRODUCTION',
  STAGING = 'STAGING',
  DEVELOPMENT = 'DEVELOPMENT',
}

@Entity({ name: 'assets' })
export class Asset {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 255 })
  hostname!: string;

  @Index()
  @Column({ type: 'varchar', length: 45, name: 'ip_address' })
  ipAddress!: string;

  @Column({
    type: 'enum',
    enum: AssetCriticality,
    default: AssetCriticality.MEDIUM,
  })
  criticality!: AssetCriticality;

  @Column({
    type: 'enum',
    enum: AssetEnvironment,
    default: AssetEnvironment.PRODUCTION,
  })
  environment!: AssetEnvironment;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
