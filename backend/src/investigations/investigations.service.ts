import { Injectable, Logger } from '@nestjs/common';
import { GraphBuilderService } from './graph-builder.service';
import { AuditService } from '../audit/audit.service';
import {
  GetIncidentGraphQueryDto,
  FindPathsQueryDto,
  BlastRadiusQueryDto,
} from './dto/investigation-query.dto';
import {
  InvestigationGraphData,
  DfsPathResult,
  BlastRadiusAnalysis,
  CycleDetectionResult,
} from './graph/graph.types';

@Injectable()
export class InvestigationsService {
  private readonly logger = new Logger(InvestigationsService.name);

  constructor(
    private readonly graphBuilder: GraphBuilderService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Builds and returns the investigation subgraph centered around an incident.
   */
  async getIncidentGraph(
    incidentId: string,
    query: GetIncidentGraphQueryDto,
    userId?: string,
    ipAddress?: string,
  ): Promise<InvestigationGraphData> {
    const graph = await this.graphBuilder.buildIncidentGraph(incidentId, {
      maxHops: query.maxHops,
      timeWindowHours: query.timeWindowHours,
      includeEvents: query.includeEvents,
      limit: query.limit,
    });

    const data = graph.toData(`incident:${incidentId}`);

    await this.auditService.logAction({
      userId,
      action: 'INVESTIGATION_GRAPH_VIEWED',
      resourceType: 'INCIDENT',
      resourceId: incidentId,
      ipAddress,
      details: {
        nodeCount: data.metadata.nodeCount,
        edgeCount: data.metadata.edgeCount,
        maxHops: query.maxHops,
      },
    });

    return data;
  }

  /**
   * Executes iterative DFS to find attack propagation paths between two nodes.
   */
  async findIncidentPaths(
    incidentId: string,
    query: FindPathsQueryDto,
    userId?: string,
    ipAddress?: string,
  ): Promise<DfsPathResult> {
    const graph = await this.graphBuilder.buildIncidentGraph(incidentId, {
      includeEvents: true,
      limit: 100,
    });

    const result = graph.findAttackPaths(
      query.sourceId,
      query.targetId,
      query.maxDepth,
      query.maxPaths,
    );

    await this.auditService.logAction({
      userId,
      action: 'ATTACK_PATHS_TRACED',
      resourceType: 'INCIDENT',
      resourceId: incidentId,
      ipAddress,
      details: {
        sourceId: query.sourceId,
        targetId: query.targetId,
        pathsFound: result.paths.length,
      },
    });

    return result;
  }

  /**
   * Computes tiered blast-radius impact analysis for the incident.
   */
  async getIncidentBlastRadius(
    incidentId: string,
    query: BlastRadiusQueryDto,
    userId?: string,
    ipAddress?: string,
  ): Promise<BlastRadiusAnalysis> {
    const graph = await this.graphBuilder.buildIncidentGraph(incidentId, {
      maxHops: query.maxHops,
      timeWindowHours: query.timeWindowHours,
      includeEvents: true,
      limit: 100,
    });

    const incidentNodeId = `incident:${incidentId}`;
    const result = graph.calculateBlastRadius(incidentNodeId, {
      maxHops: query.maxHops,
      timeWindowHours: query.timeWindowHours,
    });

    await this.auditService.logAction({
      userId,
      action: 'BLAST_RADIUS_ANALYZED',
      resourceType: 'INCIDENT',
      resourceId: incidentId,
      ipAddress,
      details: {
        directlyAffected: result.directlyAffectedCount,
        potentiallyExposed: result.potentiallyExposedCount,
        criticalAssetsAtRisk: result.criticalAssetsAtRisk.length,
      },
    });

    return result;
  }

  /**
   * Detects directed lateral movement loops or cyclic paths within the incident neighborhood.
   */
  async getIncidentCycles(
    incidentId: string,
    userId?: string,
    ipAddress?: string,
  ): Promise<CycleDetectionResult> {
    const graph = await this.graphBuilder.buildIncidentGraph(incidentId, {
      includeEvents: true,
      limit: 100,
    });

    const result = graph.detectDirectedCycles();

    await this.auditService.logAction({
      userId,
      action: 'INVESTIGATION_CYCLES_CHECKED',
      resourceType: 'INCIDENT',
      resourceId: incidentId,
      ipAddress,
      details: {
        hasCycles: result.hasCycles,
        cycleCount: result.cycleCount,
      },
    });

    return result;
  }
}
