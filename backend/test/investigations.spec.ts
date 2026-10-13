import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { AppModule } from '../src/app.module';
import { Incident, IncidentStatus } from '../src/incidents/entities/incident.entity';
import { CandidateIncident } from '../src/correlation/entities/candidate-incident.entity';
import { SecurityEvent, EventSeverity } from '../src/events/entities/security-event.entity';
import { Asset, AssetCriticality } from '../src/assets/entities/asset.entity';
import { User } from '../src/users/entities/user.entity';

describe('Milestone 2.3: Graph-Based Security Investigation & Attack Path API', () => {
  let app: INestApplication;
  let incidentRepo: Repository<Incident>;
  let candidateRepo: Repository<CandidateIncident>;
  let eventRepo: Repository<SecurityEvent>;
  let assetRepo: Repository<Asset>;

  let adminToken: string;
  let auditorToken: string;

  let testIncident: Incident;
  let testAsset: Asset;
  let testEvents: SecurityEvent[] = [];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();

    incidentRepo = app.get<Repository<Incident>>(getRepositoryToken(Incident));
    candidateRepo = app.get<Repository<CandidateIncident>>(getRepositoryToken(CandidateIncident));
    eventRepo = app.get<Repository<SecurityEvent>>(getRepositoryToken(SecurityEvent));
    assetRepo = app.get<Repository<Asset>>(getRepositoryToken(Asset));

    // Admin Token
    const adminLoginRes = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'admin@sentinelx.local', password: 'AdminPassword123!' });
    adminToken = adminLoginRes.body.accessToken;

    // Ensure Auditor user exists and generate token
    const userRepo = app.get<Repository<User>>(getRepositoryToken(User));
    let auditor = await userRepo.findOne({ where: { email: 'auditor@sentinelx.local' } });
    if (!auditor) {
      auditor = await userRepo.save(
        userRepo.create({
          id: '44444444-4444-4444-4444-444444444444',
          email: 'auditor@sentinelx.local',
          passwordHash: '$2b$10$WWeUevFbL9QUMwcZOgHEIeFpvPWOLccMm50md8vE8PFTuogM3dhGa',
          firstName: 'Auditor',
          lastName: 'Compliance',
          roleId: '44444444-4444-4444-4444-444444444444',
          isActive: true,
        }),
      );
    }

    const jwtService = app.get(JwtService);
    auditorToken = jwtService.sign({
      sub: auditor.id,
      email: auditor.email,
      role: 'READ_ONLY_AUDITOR',
      permissions: ['events:read', 'detections:read', 'incidents:read', 'audit:read'],
    });

    // Seed test Asset
    const testHostname = `core-vault-prod-${Date.now().toString().slice(-4)}`;
    testAsset = await assetRepo.save(
      assetRepo.create({
        hostname: testHostname,
        ipAddress: '10.0.50.25',
        criticality: AssetCriticality.CRITICAL,
      }),
    );

    // Seed test Events
    const now = new Date();
    const e1 = await eventRepo.save(
      eventRepo.create({
        eventType: 'PORT_SCAN',
        severity: EventSeverity.MEDIUM,
        sourceIp: '198.51.100.77',
        targetUser: 'sec-admin',
        assetId: testAsset.id,
        eventTimestamp: new Date(now.getTime() - 100000),
      }),
    );
    const e2 = await eventRepo.save(
      eventRepo.create({
        eventType: 'EXPLOIT_ATTEMPT',
        severity: EventSeverity.HIGH,
        sourceIp: '198.51.100.77',
        targetUser: 'sec-admin',
        assetId: testAsset.id,
        eventTimestamp: new Date(now.getTime() - 50000),
      }),
    );
    const e3 = await eventRepo.save(
      eventRepo.create({
        eventType: 'PRIVILEGE_ESCALATION',
        severity: EventSeverity.CRITICAL,
        sourceIp: '198.51.100.77',
        targetUser: 'sec-admin',
        assetId: testAsset.id,
        eventTimestamp: now,
      }),
    );
    testEvents = [e1, e2, e3];

    // Seed test Incident
    testIncident = await incidentRepo.save(
      incidentRepo.create({
        code: `INC-GRAPH-${Date.now().toString().slice(-4)}`,
        title: 'Exploit Chain on Core Vault',
        summary: 'Detected multi-stage kill-chain on production vault',
        severity: EventSeverity.CRITICAL,
        status: IncidentStatus.OPEN,
        sourceIp: '198.51.100.77',
      }),
    );

    // Link CandidateIncident with eventIds
    await candidateRepo.save(
      candidateRepo.create({
        id: testIncident.id,
        incidentId: testIncident.id,
        title: testIncident.title,
        summary: testIncident.summary,
        explanation: 'Correlated test exploit chain on core vault.',
        confidenceScore: 0.95,
        severity: EventSeverity.CRITICAL,
        primarySourceIp: '198.51.100.77',
        primaryUser: 'sec-admin',
        primaryAssetId: testAsset.id,
        eventIds: testEvents.map((e) => e.id),
        firstSeen: e1.eventTimestamp,
        lastSeen: e3.eventTimestamp,
      }),
    );
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('1. Incident Graph Retrieval (GET /api/v1/investigations/incident/:id/graph)', () => {
    it('should return complete graph with nodes, edges, and provenance for incident', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/graph`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.nodes).toBeDefined();
      expect(res.body.edges).toBeDefined();
      expect(res.body.metadata).toBeDefined();

      const nodes = res.body.nodes;
      const edges = res.body.edges;

      // Verify node types present
      const nodeTypes = nodes.map((n: any) => n.nodeType);
      expect(nodeTypes).toContain('INCIDENT');
      expect(nodeTypes).toContain('SECURITY_EVENT');
      expect(nodeTypes).toContain('USER');
      expect(nodeTypes).toContain('IP_ADDRESS');
      expect(nodeTypes).toContain('ASSET');

      // Verify edges present
      expect(edges.length).toBeGreaterThanOrEqual(3);
      const edgeTypes = edges.map((e: any) => e.edgeType);
      expect(edgeTypes).toContain('PART_OF_INCIDENT');
      expect(edgeTypes).toContain('CONNECTED_FROM');
      expect(edgeTypes).toContain('TARGETED_USER');

      // Verify provenance details
      const firstEdge = edges[0];
      expect(firstEdge.provenance).toBeDefined();
      expect(firstEdge.provenance.timestamp).toBeDefined();
      expect(firstEdge.provenance.confidence).toBeGreaterThan(0);
    });

    it('should support includeEvents=false to return entity-only condensed topology', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/graph?includeEvents=false`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      const nodeTypes = res.body.nodes.map((n: any) => n.nodeType);
      expect(nodeTypes).not.toContain('SECURITY_EVENT');
      expect(nodeTypes).toContain('INCIDENT');
    });

    it('should return 404 for non-existent incident id', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/investigations/incident/00000000-0000-0000-0000-000000000000/graph')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(404);
      expect(res.body.message).toContain('not found');
    });
  });

  describe('2. Attack Path Finding (GET /api/v1/investigations/incident/:id/paths)', () => {
    it('should trace attack path from external IP to target asset', async () => {
      const sourceId = 'ip:198.51.100.77';
      const targetId = `asset:${testAsset.id}`;

      const res = await request(app.getHttpServer())
        .get(
          `/api/v1/investigations/incident/${testIncident.id}/paths?sourceId=${sourceId}&targetId=${targetId}&maxDepth=4`,
        )
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.paths).toBeDefined();
      expect(Array.isArray(res.body.paths)).toBe(true);
      expect(res.body.paths.length).toBeGreaterThanOrEqual(1);

      const path = res.body.paths[0];
      expect(path.nodes.length).toBeGreaterThanOrEqual(2);
      expect(path.summary).toBeDefined();
      expect(path.totalConfidence).toBeGreaterThan(0);
    });
  });

  describe('3. Blast-Radius Analysis (GET /api/v1/investigations/incident/:id/blast-radius)', () => {
    it('should return tiered blast-radius impact with critical asset alerts and disclaimer', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/blast-radius?maxHops=2`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.targetNode).toBeDefined();
      expect(res.body.directlyAffectedCount).toBeGreaterThanOrEqual(1);
      expect(res.body.entities).toBeDefined();

      // Check critical assets at risk
      expect(res.body.criticalAssetsAtRisk).toBeDefined();
      expect(
        res.body.criticalAssetsAtRisk.some(
          (a: any) => a.assetNode.id === `asset:${testAsset.id}`,
        ),
      ).toBe(true);

      // Verify disclaimer
      expect(res.body.disclaimer).toContain(
        'reachability alone does not constitute forensic evidence of asset compromise',
      );
    });
  });

  describe('4. Cycle Detection (GET /api/v1/investigations/incident/:id/cycles)', () => {
    it('should return cycle analysis result', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/cycles`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.hasCycles).toBeDefined();
      expect(res.body.analysisSummary).toBeDefined();
    });
  });

  describe('5. Authorization, RBAC & Parameter Validation', () => {
    it('should allow READ_ONLY_AUDITOR to inspect incident graph', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/graph`)
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.nodes).toBeDefined();
    });

    it('should reject unauthenticated requests with 401 Unauthorized', async () => {
      const res = await request(app.getHttpServer()).get(
        `/api/v1/investigations/incident/${testIncident.id}/graph`,
      );

      expect(res.status).toBe(401);
    });

    it('should enforce parameter validation ceiling limits (maxHops > 5 rejected with 400)', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/investigations/incident/${testIncident.id}/graph?maxHops=99`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('maxHops must not be greater than 5');
    });
  });
});
