import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

export interface CreateAuditLogParams {
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  ipAddress?: string;
  details?: Record<string, any>;
}

@Injectable()
export class AuditService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditRepo: Repository<AuditLog>,
  ) {}

  private sanitizeDetails(details?: Record<string, any>): Record<string, any> {
    if (!details) return {};
    const sanitized = { ...details };
    const forbiddenKeys = ['password', 'passwordHash', 'token', 'accessToken', 'refreshToken', 'secret'];
    for (const key of Object.keys(sanitized)) {
      if (forbiddenKeys.some((f) => key.toLowerCase().includes(f.toLowerCase()))) {
        sanitized[key] = '[REDACTED]';
      }
    }
    return sanitized;
  }

  async logAction(params: CreateAuditLogParams): Promise<AuditLog> {
    const entry = this.auditRepo.create({
      userId: params.userId,
      action: params.action,
      resourceType: params.resourceType,
      resourceId: params.resourceId,
      ipAddress: params.ipAddress,
      details: this.sanitizeDetails(params.details),
    });
    return this.auditRepo.save(entry);
  }

  async getRecentLogs(limit: number = 50, offset: number = 0): Promise<{ data: AuditLog[]; total: number }> {
    const [data, total] = await this.auditRepo.findAndCount({
      order: { timestamp: 'DESC' },
      take: Math.min(limit, 100),
      skip: offset,
      relations: ['user'],
    });
    return { data, total };
  }
}
