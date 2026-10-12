import { EventSeverity } from '../events/entities/security-event.entity';

export interface SecurityEventEnvelope {
  envelopeId: string;
  idempotencyKey: string;
  version: string;
  ingestedAt: string;
  event: {
    category: string;
    type: string;
    severity: EventSeverity;
    timestamp: string;
  };
  source: {
    ip: string;
    port?: number;
  };
  destination?: {
    ip?: string;
    port?: number;
  };
  user?: {
    name?: string;
    role?: string;
  };
  host?: {
    hostname?: string;
    criticality?: string;
  };
  rawPayload: Record<string, any>;
  normalizedDetails: Record<string, any>;
}

export interface StreamMessage<T = any> {
  topic: string;
  key: string;
  value: T;
  headers?: Record<string, string>;
  partition?: number;
  offset?: number;
  timestamp?: number;
}

export interface ConsumerLagInfo {
  topic: string;
  partition: number;
  currentOffset: number;
  highWatermark: number;
  lag: number;
}

export interface StreamingStats {
  driver: 'kafka' | 'embedded';
  status: 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED';
  topics: string[];
  totalPublished: number;
  totalConsumed: number;
  totalRetried: number;
  totalDeadLettered: number;
  lag: ConsumerLagInfo[];
}
