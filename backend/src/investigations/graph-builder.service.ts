import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, Between } from 'typeorm';
import { Incident } from '../incidents/entities/incident.entity';
import { CandidateIncident } from '../correlation/entities/candidate-incident.entity';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { Asset } from '../assets/entities/asset.entity';
import { Detection } from '../detections/entities/detection.entity';
import { InvestigationGraph } from './graph/investigation.graph';
import {
  GraphNodeType,
  GraphEdgeType,
  GraphNode,
  GraphEdge,
} from './graph/graph.types';

const ATTACK_PROGRESSIONS = new Set([
  'AUTH_FAILURE->AUTH_SUCCESS',
  'AUTH_FAILURE->PRIVILEGE_ESCALATION',
  'AUTH_SUCCESS->PRIVILEGE_ESCALATION',
  'PRIVILEGE_ESCALATION->SUSPICIOUS_PROCESS',
  'PRIVILEGE_ESCALATION->DATA_EXFILTRATION',
  'SUSPICIOUS_PROCESS->DATA_EXFILTRATION',
  'PORT_SCAN->AUTH_FAILURE',
  'PORT_SCAN->EXPLOIT_ATTEMPT',
  'EXPLOIT_ATTEMPT->PRIVILEGE_ESCALATION',
]);

@Injectable()
export class GraphBuilderService {
  private readonly logger = new Logger(GraphBuilderService.name);

  constructor(
    @InjectRepository(Incident)
    private readonly incidentRepo: Repository<Incident>,
    @InjectRepository(CandidateIncident)
    private readonly candidateRepo: Repository<CandidateIncident>,
    @InjectRepository(SecurityEvent)
    private readonly eventRepo: Repository<SecurityEvent>,
    @InjectRepository(Asset)
    private readonly assetRepo: Repository<Asset>,
    @InjectRepository(Detection)
    private readonly detectionRepo: Repository<Detection>,
  ) {}

  /**
   * Constructs an InvestigationGraph centered around a confirmed Incident.
   */
  async buildIncidentGraph(
    incidentId: string,
    options: {
      maxHops?: number;
      timeWindowHours?: number;
      includeEvents?: boolean;
      limit?: number;
    } = {},
  ): Promise<InvestigationGraph> {
    const incident = await this.incidentRepo.findOne({
      where: { id: incidentId },
      relations: ['detection', 'assignedTo'],
    });

    if (!incident) {
      throw new NotFoundException(`Incident with id '${incidentId}' not found.`);
    }

    const graph = new InvestigationGraph();
    const timeWindowHours = options.timeWindowHours || 24;
    const windowMs = timeWindowHours * 60 * 60 * 1000;
    const centerTime = incident.createdAt.getTime();
    const startTime = new Date(centerTime - windowMs);
    const endTime = new Date(centerTime + windowMs);

    // 1. Add Incident root node
    const incidentNodeId = `incident:${incident.id}`;
    graph.addNode({
      id: incidentNodeId,
      nodeType: GraphNodeType.INCIDENT,
      label: `${incident.code}: ${incident.title}`,
      properties: {
        entityId: incident.id,
        code: incident.code,
        severity: incident.severity,
        status: incident.status,
        sourceIp: incident.sourceIp,
        createdAt: incident.createdAt.toISOString(),
      },
    });

    // 2. Add Detection node if linked directly
    if (incident.detection) {
      const detectionNodeId = `detection:${incident.detection.id}`;
      graph.addNode({
        id: detectionNodeId,
        nodeType: GraphNodeType.DETECTION,
        label: `Detection: ${incident.detection.ruleName}`,
        properties: {
          entityId: incident.detection.id,
          ruleId: incident.detection.ruleId,
          ruleName: incident.detection.ruleName,
          severity: incident.detection.severity,
          triggerCount: incident.detection.triggerCount,
          detectedAt: incident.detection.detectedAt.toISOString(),
        },
      });

      graph.addEdge({
        id: `${detectionNodeId}->PART_OF_INCIDENT->${incidentNodeId}`,
        sourceNodeId: detectionNodeId,
        targetNodeId: incidentNodeId,
        edgeType: GraphEdgeType.PART_OF_INCIDENT,
        label: 'Part of Incident',
        isDirected: true,
        provenance: {
          sourceRecordId: incident.detection.id,
          recordType: 'DETECTION',
          timestamp: incident.detection.detectedAt.toISOString(),
          confidence: 1.0,
        },
      });
    }

    // 3. Find linked CandidateIncident (provenance bridge)
    const candidate = await this.candidateRepo.findOne({
      where: [{ incidentId: incident.id }, { id: incident.id }],
    });

    const eventIdsToFetch = new Set<string>();
    if (candidate && candidate.eventIds && candidate.eventIds.length > 0) {
      for (const id of candidate.eventIds) {
        eventIdsToFetch.add(id);
      }
    }

    // 4. Query associated security events
    let events: SecurityEvent[] = [];
    if (eventIdsToFetch.size > 0) {
      events = await this.eventRepo.find({
        where: { id: In(Array.from(eventIdsToFetch)) },
        order: { eventTimestamp: 'ASC' },
        take: options.limit || 100,
      });
    }

    // If candidate had no explicit event IDs, query events matching source IP or asset in time window
    if (events.length === 0 && incident.sourceIp) {
      events = await this.eventRepo.find({
        where: {
          sourceIp: incident.sourceIp,
          eventTimestamp: Between(startTime, endTime),
        },
        order: { eventTimestamp: 'ASC' },
        take: options.limit || 100,
      });
    }

    // Collect asset IDs from events
    const assetIds = new Set<string>();
    if (candidate?.primaryAssetId) {
      assetIds.add(candidate.primaryAssetId);
    }
    for (const evt of events) {
      if (evt.assetId) assetIds.add(evt.assetId);
    }

    // Query asset metadata
    let assets: Asset[] = [];
    if (assetIds.size > 0) {
      assets = await this.assetRepo.find({
        where: { id: In(Array.from(assetIds)) },
      });
    }
    const assetMap = new Map<string, Asset>(assets.map((a) => [a.id, a]));

    // 5. Populate nodes and edges from events
    const userNodes = new Set<string>();
    const ipNodes = new Set<string>();

    for (const evt of events) {
      const eventNodeId = `event:${evt.id}`;

      if (options.includeEvents !== false) {
        graph.addNode({
          id: eventNodeId,
          nodeType: GraphNodeType.SECURITY_EVENT,
          label: `${evt.eventType} (${evt.severity})`,
          properties: {
            entityId: evt.id,
            eventType: evt.eventType,
            severity: evt.severity,
            sourceIp: evt.sourceIp,
            targetUser: evt.targetUser,
            assetId: evt.assetId,
            timestamp: evt.eventTimestamp.toISOString(),
          },
        });

        graph.addEdge({
          id: `${eventNodeId}->PART_OF_INCIDENT->${incidentNodeId}`,
          sourceNodeId: eventNodeId,
          targetNodeId: incidentNodeId,
          edgeType: GraphEdgeType.PART_OF_INCIDENT,
          label: 'Implicated In',
          isDirected: true,
          provenance: {
            sourceRecordId: evt.id,
            recordType: 'SECURITY_EVENT',
            timestamp: evt.eventTimestamp.toISOString(),
            confidence: 1.0,
          },
        });
      }

      // Source IP node
      if (evt.sourceIp) {
        const ipNodeId = `ip:${evt.sourceIp}`;
        if (!graph.hasNode(ipNodeId)) {
          graph.addNode({
            id: ipNodeId,
            nodeType: GraphNodeType.IP_ADDRESS,
            label: evt.sourceIp,
            properties: {
              ipAddress: evt.sourceIp,
              isInternal: this.isPrivateIp(evt.sourceIp),
            },
          });
        }
        ipNodes.add(ipNodeId);

        if (options.includeEvents !== false) {
          graph.addEdge({
            id: `${ipNodeId}->CONNECTED_FROM->${eventNodeId}`,
            sourceNodeId: ipNodeId,
            targetNodeId: eventNodeId,
            edgeType: GraphEdgeType.CONNECTED_FROM,
            label: 'Observed Source',
            isDirected: true,
            provenance: {
              sourceRecordId: evt.id,
              recordType: 'SECURITY_EVENT',
              timestamp: evt.eventTimestamp.toISOString(),
              confidence: 1.0,
            },
          });
        }
      }

      // Target User node
      if (evt.targetUser) {
        const userNodeId = `user:${evt.targetUser.toLowerCase()}`;
        if (!graph.hasNode(userNodeId)) {
          graph.addNode({
            id: userNodeId,
            nodeType: GraphNodeType.USER,
            label: evt.targetUser,
            properties: {
              username: evt.targetUser,
            },
          });
        }
        userNodes.add(userNodeId);

        if (options.includeEvents !== false) {
          graph.addEdge({
            id: `${eventNodeId}->TARGETED_USER->${userNodeId}`,
            sourceNodeId: eventNodeId,
            targetNodeId: userNodeId,
            edgeType: GraphEdgeType.TARGETED_USER,
            label: 'Target Identity',
            isDirected: true,
            provenance: {
              sourceRecordId: evt.id,
              recordType: 'SECURITY_EVENT',
              timestamp: evt.eventTimestamp.toISOString(),
              confidence: 1.0,
            },
          });
        }

        // If authentication event, link IP -> User
        if (evt.sourceIp && (evt.eventType.includes('AUTH') || evt.eventType.includes('LOGIN'))) {
          const ipNodeId = `ip:${evt.sourceIp}`;
          graph.addEdge({
            id: `${ipNodeId}->AUTHENTICATED_AS->${userNodeId}`,
            sourceNodeId: ipNodeId,
            targetNodeId: userNodeId,
            edgeType: GraphEdgeType.AUTHENTICATED_AS,
            label: evt.eventType,
            isDirected: true,
            provenance: {
              sourceRecordId: evt.id,
              recordType: 'SECURITY_EVENT',
              timestamp: evt.eventTimestamp.toISOString(),
              confidence: evt.eventType.includes('SUCCESS') ? 1.0 : 0.7,
            },
          });
        }
      }

      // Asset node
      if (evt.assetId) {
        const assetObj = assetMap.get(evt.assetId);
        const assetNodeId = `asset:${evt.assetId}`;

        if (!graph.hasNode(assetNodeId)) {
          graph.addNode({
            id: assetNodeId,
            nodeType: GraphNodeType.ASSET,
            label: assetObj ? `${assetObj.hostname} (${assetObj.criticality})` : `Asset ${evt.assetId}`,
            properties: {
              entityId: evt.assetId,
              hostname: assetObj?.hostname,
              ipAddress: assetObj?.ipAddress,
              criticality: assetObj?.criticality || 'MEDIUM',
              environment: assetObj?.environment || 'PRODUCTION',
            },
          });

          // Link asset to its bound network IP
          if (assetObj?.ipAddress) {
            const assetIpNodeId = `ip:${assetObj.ipAddress}`;
            if (!graph.hasNode(assetIpNodeId)) {
              graph.addNode({
                id: assetIpNodeId,
                nodeType: GraphNodeType.IP_ADDRESS,
                label: assetObj.ipAddress,
                properties: {
                  ipAddress: assetObj.ipAddress,
                  isInternal: this.isPrivateIp(assetObj.ipAddress),
                },
              });
            }
            graph.addEdge({
              id: `${assetNodeId}->RESOLVES_TO->${assetIpNodeId}`,
              sourceNodeId: assetNodeId,
              targetNodeId: assetIpNodeId,
              edgeType: GraphEdgeType.RESOLVES_TO,
              label: 'Host Interface',
              isDirected: true,
              provenance: {
                sourceRecordId: assetObj.id,
                recordType: 'ASSET_INVENTORY',
                timestamp: assetObj.createdAt?.toISOString() || new Date().toISOString(),
                confidence: 1.0,
              },
            });
          }
        }

        if (options.includeEvents !== false) {
          graph.addEdge({
            id: `${eventNodeId}->TARGETED_ASSET->${assetNodeId}`,
            sourceNodeId: eventNodeId,
            targetNodeId: assetNodeId,
            edgeType: GraphEdgeType.TARGETED_ASSET,
            label: 'Target Asset',
            isDirected: true,
            provenance: {
              sourceRecordId: evt.id,
              recordType: 'SECURITY_EVENT',
              timestamp: evt.eventTimestamp.toISOString(),
              confidence: 1.0,
            },
          });
        }
      }
    }

    // 6. Connect MITRE kill-chain progression between consecutive events
    if (options.includeEvents !== false && events.length > 1) {
      for (let i = 0; i < events.length - 1; i++) {
        const e1 = events[i];
        const e2 = events[i + 1];
        const key = `${e1.eventType}->${e2.eventType}`;

        if (ATTACK_PROGRESSIONS.has(key)) {
          const e1Id = `event:${e1.id}`;
          const e2Id = `event:${e2.id}`;
          if (graph.hasNode(e1Id) && graph.hasNode(e2Id)) {
            graph.addEdge({
              id: `${e1Id}->PRECEDED_BY->${e2Id}`,
              sourceNodeId: e1Id,
              targetNodeId: e2Id,
              edgeType: GraphEdgeType.PRECEDED_BY,
              label: key,
              isDirected: true,
              provenance: {
                sourceRecordId: `${e1.id}->${e2.id}`,
                recordType: 'ATTACK_PROGRESSION',
                timestamp: e2.eventTimestamp.toISOString(),
                confidence: 0.9,
              },
            });
          }
        }
      }
    }

    return graph;
  }

  private isPrivateIp(ip: string): boolean {
    if (!ip) return false;
    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('127.') ||
      ip === '::1'
    );
  }
}
