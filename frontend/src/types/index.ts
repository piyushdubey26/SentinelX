export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export interface Incident {
  id: string;
  code: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  timestamp: string;
  sourceIp?: string;
  assignee?: string;
  summary?: string;
}

export interface BackendHealth {
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
