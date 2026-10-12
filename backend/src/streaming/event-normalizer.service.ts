import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import { IngestEventDto } from '../events/dto/ingest-event.dto';
import { EventSeverity } from '../events/entities/security-event.entity';
import { SecurityEventEnvelope } from './streaming.types';

@Injectable()
export class EventNormalizerService {
  /**
   * Normalizes incoming raw telemetry into an Elastic Common Schema (ECS) aligned envelope.
   */
  normalize(dto: IngestEventDto, clientIp?: string): SecurityEventEnvelope {
    const envelopeId = crypto.randomUUID();
    const eventTimestamp = dto.eventTimestamp || new Date().toISOString();
    const ingestedAt = new Date().toISOString();

    // Determine category based on event type
    const category = this.mapCategory(dto.eventType);

    // Compute or extract idempotency key
    const idempotencyKey =
      (dto as any).idempotencyKey ||
      this.generateIdempotencyKey(dto, eventTimestamp);

    const normalizedSourceIp = (dto.sourceIp || clientIp || '127.0.0.1').trim();
    const normalizedTargetUser = dto.targetUser ? dto.targetUser.toLowerCase().trim() : undefined;

    const normalizedDetails: Record<string, any> = {
      normalizedSourceIp,
      normalizedTargetUser,
      ingestedFromIp: clientIp,
      protocol: 'HTTPS',
      enrichment: {
        isPrivateIp: this.isPrivateIp(normalizedSourceIp),
        category,
      },
    };

    return {
      envelopeId,
      idempotencyKey,
      version: '2.0',
      ingestedAt,
      event: {
        category,
        type: dto.eventType,
        severity: dto.severity || EventSeverity.INFO,
        timestamp: eventTimestamp,
      },
      source: {
        ip: normalizedSourceIp,
        port: dto.sourcePort,
      },
      destination: {
        ip: dto.destinationIp,
      },
      user: normalizedTargetUser
        ? {
            name: normalizedTargetUser,
          }
        : undefined,
      rawPayload: dto.rawPayload || {},
      normalizedDetails,
    };
  }

  private mapCategory(eventType: string): string {
    const upper = eventType.toUpperCase();
    if (upper.includes('AUTH') || upper.includes('LOGIN') || upper.includes('CREDENTIAL')) {
      return 'authentication';
    }
    if (upper.includes('SCAN') || upper.includes('TRAFFIC') || upper.includes('PORT') || upper.includes('DDOS')) {
      return 'network';
    }
    if (upper.includes('PRIVILEGE') || upper.includes('SUDO') || upper.includes('ROLE')) {
      return 'iam';
    }
    if (upper.includes('PROCESS') || upper.includes('EXEC') || upper.includes('COMMAND')) {
      return 'process';
    }
    return 'security';
  }

  private generateIdempotencyKey(dto: IngestEventDto, timestamp: string): string {
    const payloadStr = JSON.stringify(dto.rawPayload || {});
    const input = `${dto.eventType}:${dto.sourceIp}:${dto.targetUser || ''}:${dto.sourcePort || ''}:${timestamp}:${payloadStr}`;
    return crypto.createHash('sha256').update(input).digest('hex');
  }

  private isPrivateIp(ip: string): boolean {
    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('127.') ||
      ip.startsWith('172.16.') ||
      ip === '::1'
    );
  }
}
