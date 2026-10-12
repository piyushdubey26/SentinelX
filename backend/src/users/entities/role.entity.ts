import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { User } from './user.entity';

export enum RoleType {
  ADMIN = 'ADMIN',
  SECURITY_ENGINEER = 'SECURITY_ENGINEER',
  SOC_ANALYST = 'SOC_ANALYST',
  READ_ONLY_AUDITOR = 'READ_ONLY_AUDITOR',
}

@Entity({ name: 'roles' })
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 50, unique: true })
  name!: RoleType;

  @Column({ type: 'varchar', length: 255 })
  description!: string;

  @Column({ type: 'text', array: true, default: '{}' })
  permissions!: string[];

  @OneToMany(() => User, (user) => user.role)
  users!: User[];

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
