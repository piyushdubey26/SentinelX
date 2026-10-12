import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptimeSeconds: number;
  environment: string;
  database: {
    connected: boolean;
    databaseName: string;
  };
  version: string;
}

@Injectable()
export class HealthService {
  constructor(private readonly dataSource: DataSource) {}

  async check(): Promise<HealthCheckResponse> {
    let dbConnected = false;
    let dbName = 'unknown';

    try {
      if (this.dataSource.isInitialized) {
        await this.dataSource.query('SELECT 1');
        dbConnected = true;
        dbName = (this.dataSource.options as any).database || 'sentinelx';
      }
    } catch {
      dbConnected = false;
    }

    return {
      status: dbConnected ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      environment: process.env.NODE_ENV || 'development',
      database: {
        connected: dbConnected,
        databaseName: dbName,
      },
      version: '0.1.0',
    };
  }
}
