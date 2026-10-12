import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { CorrelationService } from '../src/correlation/correlation.service';
import { CorrelationEngine } from '../src/correlation/correlation.engine';
import {
  CandidateIncidentStatus,
  CorrelationFactorType,
  DEFAULT_CORRELATION_CONFIG,
} from '../src/correlation/correlation.types';
import { SecurityEvent, EventSeverity } from '../src/events/entities/security-event.entity';
import { CandidateIncident } from '../src/correlation/entities/candidate-incident.entity';
import { Incident } from '../src/incidents/entities/incident.entity';
import { User } from '../src/users/entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { JwtService } from '@nestjs/jwt';

describe('Milestone 2.2: Event Correlation Engine, Candidate Lifecycle & Anti-IP-Bleeding Safety', () => {
  let app: INestApplication;
  let correlationService: CorrelationService;
  let correlationEngine: CorrelationEngine;
  let eventRepo: Repository<SecurityEvent>;
  let candidateRepo: Repository<CandidateIncident>;
  let incidentRepo: Repository<Incident>;

  let adminToken: string;
  let auditorToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();

    correlationService = app.get(CorrelationService);
    correlationEngine = correlationService.getEngine();
    eventRepo = app.get<Repository<SecurityEvent>>(getRepositoryToken(SecurityEvent));
    candidateRepo = app.get<Repository<CandidateIncident>>(getRepositoryToken(CandidateIncident));
    incidentRepo = app.get<Repository<Incident>>(getRepositoryToken(Incident));

    // Authenticate Admin
    const adminLoginRes = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'admin@sentinelx.local', password: 'AdminPassword123!' });
    adminToken = adminLoginRes.body.accessToken;

    // Ensure Auditor exists in DB for JWT validation
    const userRepo = app.get<Repository<User>>(getRepositoryToken(User));
    let auditor = await userRepo.findOne({ where: { email: 'auditor@sentinelx.local' } });
    if (!auditor) {
      auditor = userRepo.create({
        id: '44444444-4444-4444-4444-444444444444',
        email: 'auditor@sentinelx.local',
        passwordHash: '$2b$10$WWeUevFbL9QUMwcZOgHEIeFpvPWOLccMm50md8vE8PFTuogM3dhGa',
        firstName: 'Auditor',
        lastName: 'Compliance',
        roleId: '44444444-4444-4444-4444-444444444444',
        isActive: true,
      });
      await userRepo.save(auditor);
    }

    // Issue token for Auditor (Read Only)
    const jwtService = app.get(JwtService);
    auditorToken = jwtService.sign({
      sub: auditor.id,
      email: auditor.email,
      role: 'READ_ONLY_AUDITOR',
      permissions: ['events:read', 'detections:read', 'incidents:read', 'audit:read'],
    });
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('1. Correlation Safety & Anti-IP-Bleeding Safeguards', () => {
    it('NEGATIVE TEST: should strictly reject merging events that only share a source IP (NAT/VPN/Proxy safety)', async () => {
      const sharedNatIp = '198.51.100.99';
      const now = new Date();

      // Event 1 from shared NAT: Alice accessing internal wiki
      const eventAlice = eventRepo.create({
        eventType: 'AUTH_SUCCESS',
        severity: EventSeverity.INFO,
        sourceIp: sharedNatIp,
        targetUser: 'alice@corp.local',
        rawPayload: { service: 'wiki' },
        normalizedDetails: {},
        eventTimestamp: now,
      });
      const savedAlice = await eventRepo.save(eventAlice);

      // Ingest Alice -> creates Candidate Cluster 1
      const resAlice = await correlationService.processEvent(savedAlice);
      expect(resAlice.isNewCandidate).toBe(true);
      expect(resAlice.candidate.primaryUser).toBe('alice@corp.local');

      // Event 2 from SAME shared NAT: Bob accessing payroll
      const eventBob = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: sharedNatIp,
        targetUser: 'bob@corp.local', // Different user!
        rawPayload: { service: 'payroll' },
        normalizedDetails: {},
        eventTimestamp: new Date(now.getTime() + 10000), // 10s later
      });
      const savedBob = await eventRepo.save(eventBob);

      // Ingest Bob -> MUST NOT merge with Alice's cluster!
      const resBob = await correlationService.processEvent(savedBob);
      expect(resBob.isNewCandidate).toBe(true); // Must initiate separate candidate!
      expect(resBob.candidate.id).not.toBe(resAlice.candidate.id);

      // Compare directly using engine to verify rejected factor
      const comparison = correlationEngine.compareEvents(savedAlice, savedBob);
      expect(comparison.isCorrelated).toBe(false);
      expect(comparison.score).toBe(0);

      const rejectedIpFactor = comparison.rejectedFactors.find(
        (f) => f.factorType === CorrelationFactorType.SHARED_SOURCE_IP_REJECTED,
      );
      expect(rejectedIpFactor).toBeDefined();
      expect(rejectedIpFactor?.description).toContain('ANTI_IP_BLEEDING');
    });

    it('POSITIVE TEST: should correlate multi-attribute match (shared identity + reinforced IP) with high confidence', async () => {
      const attackIp = '203.0.113.45';
      const targetUser = 'victim-user-1@sentinelx.local';
      const now = new Date();

      // Step 1: Failed SSH attempt
      const event1 = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.HIGH,
        sourceIp: attackIp,
        targetUser,
        rawPayload: { attempt: 1 },
        normalizedDetails: {},
        eventTimestamp: now,
      });
      const saved1 = await eventRepo.save(event1);
      const res1 = await correlationService.processEvent(saved1);

      // Step 2: Privilege escalation attempt by same user from same IP
      const event2 = eventRepo.create({
        eventType: 'PRIVILEGE_ESCALATION',
        severity: EventSeverity.CRITICAL,
        sourceIp: attackIp,
        targetUser,
        rawPayload: { command: 'sudo -i' },
        normalizedDetails: {},
        eventTimestamp: new Date(now.getTime() + 60000), // 1 minute later
      });
      const saved2 = await eventRepo.save(event2);
      const res2 = await correlationService.processEvent(saved2);

      expect(res2.isNewCandidate).toBe(false); // Merged into existing candidate!
      expect(res2.candidate.id).toBe(res1.candidate.id);
      expect(res2.candidate.eventIds).toContain(saved1.id);
      expect(res2.candidate.eventIds).toContain(saved2.id);

      // Multi-attribute score: Identity (0.35) + Attack Progression (0.25) + Reinforced IP (0.15) = 0.75
      expect(res2.candidate.confidenceScore).toBe(0.75);
      expect(res2.candidate.explanation).toContain('Correlated with cluster');
      expect(res2.candidate.explanation).toContain('Shared target identity');
      expect(
        res2.candidate.correlationFactors.some(
          (f) => f.factorType === CorrelationFactorType.SHARED_IDENTITY,
        ),
      ).toBe(true);
    });

    it('BOUNDARY TEST (BELOW THRESHOLD): score 0.350 < 0.500 (Identity alone across different IPs) should not correlate', async () => {
      const now = new Date();
      const user = 'boundary-sub-user@sentinelx.local';

      // Event 1 from IP 1
      const event1 = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: '198.51.100.111',
          targetUser: user,
          eventTimestamp: now,
        }),
      );

      // Event 2 from DIFFERENT IP 2 (Identity alone: 0.350 < 0.500)
      const event2 = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: '198.51.100.112',
          targetUser: user,
          eventTimestamp: new Date(now.getTime() + 5000),
        }),
      );
      const comparison = correlationEngine.compareEvents(event1, event2);
      expect(comparison.score).toBe(0.35);
      expect(comparison.isCorrelated).toBe(false); // Below 0.50 threshold!
    });

    it('BOUNDARY TEST (EXACTLY AT THRESHOLD 0.500): score 0.500 = 0.500 (Identity 0.35 + Reinforced IP 0.15) correlates', async () => {
      const now = new Date();
      const user = 'boundary-threshold-user@sentinelx.local';
      const ip = '198.51.100.150';

      const event1 = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: ip,
          targetUser: user,
          eventTimestamp: now,
        }),
      );

      // Event 2: Same User + Same IP (Score: 0.35 + 0.15 = 0.500)
      const event2 = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: ip,
          targetUser: user,
          eventTimestamp: new Date(now.getTime() + 8000),
        }),
      );
      const comparison = correlationEngine.compareEvents(event1, event2);
      expect(comparison.score).toBe(0.5);
      expect(comparison.isCorrelated).toBe(true); // Meets 0.50 threshold!
    });

    it('BOUNDARY TEST (EXACTLY AT THRESHOLD 0.500 via ASSET+PROGRESSION): score 0.500 (Asset 0.25 + Progression 0.25) correlates', async () => {
      const now = new Date();
      const mockAssetId = 'aaaaaaa1-1111-1111-1111-111111111111'; // auth-gateway-prod-01 from seed

      // Event 1: Port scan on asset from IP 1
      const event1 = await eventRepo.save(
        eventRepo.create({
          eventType: 'PORT_SCAN',
          sourceIp: '198.51.100.201',
          assetId: mockAssetId,
          eventTimestamp: now,
        }),
      );

      // Event 2: Exploit attempt on same asset from IP 2
      // Score: Asset (0.25) + Progression PORT_SCAN->EXPLOIT_ATTEMPT (0.25) = 0.500 >= 0.500
      const event2 = await eventRepo.save(
        eventRepo.create({
          eventType: 'EXPLOIT_ATTEMPT',
          sourceIp: '198.51.100.202',
          assetId: mockAssetId,
          eventTimestamp: new Date(now.getTime() + 15000),
        }),
      );
      const comparison = correlationEngine.compareEvents(event1, event2);
      expect(comparison.score).toBe(0.5);
      expect(comparison.isCorrelated).toBe(true);
    });

    it('BOUNDARY TEST (FULL SATURATION): score 1.000 when all 4 dimensions match without artificial clipping', async () => {
      const now = new Date();
      const mockAssetId = 'aaaaaaa1-1111-1111-1111-111111111111';
      const ip = '198.51.100.250';
      const user = 'admin-victim';

      const event1 = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: ip,
          targetUser: user,
          assetId: mockAssetId,
          eventTimestamp: now,
        }),
      );

      // Event 2: Same IP + Same User + Same Asset + Attack Progression (AUTH_FAILURE -> PRIVILEGE_ESCALATION)
      // Score: Identity (0.35) + Asset (0.25) + Progression (0.25) + IP (0.15) = 1.000 exactly!
      const event2 = await eventRepo.save(
        eventRepo.create({
          eventType: 'PRIVILEGE_ESCALATION',
          sourceIp: ip,
          targetUser: user,
          assetId: mockAssetId,
          eventTimestamp: new Date(now.getTime() + 20000),
        }),
      );
      const comparison = correlationEngine.compareEvents(event1, event2);
      expect(comparison.score).toBe(1.0);
      expect(comparison.isCorrelated).toBe(true);
      expect(comparison.factors.length).toBe(4);
    });
  });

  describe('2. DSA Temporal Window, Out-of-Order Handling & Eviction', () => {
    it('should correctly merge out-of-order events within the temporal window and expand firstSeen', async () => {
      const baseTime = Date.now();
      const user = 'out-of-order-user@sentinelx.local';
      const ip = '192.0.2.10';

      // Event at t = 60s
      const eventLater = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: ip,
        targetUser: user,
        rawPayload: {},
        normalizedDetails: {},
        eventTimestamp: new Date(baseTime + 60000),
      });
      const savedLater = await eventRepo.save(eventLater);
      const resLater = await correlationService.processEvent(savedLater);

      // Out-of-order event arriving later but timestamped at t = 10s (earlier)
      const eventEarlier = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: ip,
        targetUser: user,
        rawPayload: {},
        normalizedDetails: {},
        eventTimestamp: new Date(baseTime + 10000),
      });
      const savedEarlier = await eventRepo.save(eventEarlier);
      const resEarlier = await correlationService.processEvent(savedEarlier);

      expect(resEarlier.isNewCandidate).toBe(false);
      expect(resEarlier.candidate.id).toBe(resLater.candidate.id);

      // Verify firstSeen was updated to the earlier event's timestamp
      const clusterState = correlationEngine.getCluster(resLater.candidate.id);
      expect(clusterState?.firstSeen).toBe(baseTime + 10000);
      expect(clusterState?.lastSeen).toBe(baseTime + 60000);
    });

    it('should not correlate events that fall outside the sliding window TTL (15 minutes)', async () => {
      const baseTime = Date.now();
      const user = 'window-expiry-user@sentinelx.local';
      const ip = '192.0.2.20';

      // Event 1 at t = 0
      const event1 = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: ip,
        targetUser: user,
        rawPayload: {},
        normalizedDetails: {},
        eventTimestamp: new Date(baseTime),
      });
      const saved1 = await eventRepo.save(event1);
      const res1 = await correlationService.processEvent(saved1);

      // Event 2 at t = 20 minutes (exceeds 15m window)
      const event2 = eventRepo.create({
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: ip,
        targetUser: user,
        rawPayload: {},
        normalizedDetails: {},
        eventTimestamp: new Date(baseTime + 20 * 60 * 1000),
      });
      const saved2 = await eventRepo.save(event2);
      const res2 = await correlationService.processEvent(saved2);

      // Must be a distinct candidate cluster
      expect(res2.isNewCandidate).toBe(true);
      expect(res2.candidate.id).not.toBe(res1.candidate.id);
    });

    it('should evict expired clusters from memory during sliding-window garbage collection', () => {
      const testEngine = new CorrelationEngine({
        ...DEFAULT_CORRELATION_CONFIG,
        slidingWindowSeconds: 60, // 60s TTL for test
      });

      const oldTime = Date.now() - 120000; // 2 minutes ago
      const mockEvent = {
        id: 'mock-1',
        eventType: 'AUTH_FAILURE',
        severity: EventSeverity.MEDIUM,
        sourceIp: '10.0.0.1',
        targetUser: 'old-user',
        eventTimestamp: new Date(oldTime),
      } as SecurityEvent;

      testEngine.ingest(mockEvent);
      expect(testEngine.getClusterCount()).toBe(1);

      // Run eviction
      const evicted = testEngine.evictExpired(Date.now());
      expect(evicted.length).toBe(1);
      expect(testEngine.getClusterCount()).toBe(0);
    });
  });

  describe('3. Candidate Incident Lifecycle & State Transitions', () => {
    let candidateToPromote: CandidateIncident;

    beforeEach(async () => {
      const event = eventRepo.create({
        eventType: 'SUSPICIOUS_PROCESS',
        severity: EventSeverity.HIGH,
        sourceIp: '198.51.100.77',
        targetUser: 'triage-user',
        rawPayload: { process: 'mimikatz.exe' },
        normalizedDetails: {},
        eventTimestamp: new Date(),
      });
      const saved = await eventRepo.save(event);
      const result = await correlationService.processEvent(saved);
      candidateToPromote = result.candidate;
    });

    it('should promote candidate incident to an official incident with provenance', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${candidateToPromote.id}/promote`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(201);
      expect(res.body.status).toBe(CandidateIncidentStatus.PROMOTED);
      expect(res.body.incidentId).toBeDefined();

      // Check official incident was created
      const officialIncident = await incidentRepo.findOne({ where: { id: res.body.incidentId } });
      expect(officialIncident).toBeDefined();
      expect(officialIncident?.title).toContain(candidateToPromote.title);
      expect(officialIncident?.code).toMatch(/^INC-\d+/);
    });

    it('IDEMPOTENCY: should return existing promoted candidate and avoid duplicate incidents on repeated promotion', async () => {
      // First promotion
      const firstRes = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${candidateToPromote.id}/promote`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(firstRes.status).toBe(201);
      const originalIncidentId = firstRes.body.incidentId;

      // Second promotion (retry / concurrent)
      const secondRes = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${candidateToPromote.id}/promote`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(secondRes.status).toBe(201);
      expect(secondRes.body.incidentId).toBe(originalIncidentId);

      // Verify no duplicate incident was created
      const matchingIncidents = await incidentRepo.find({
        where: { id: originalIncidentId },
      });
      expect(matchingIncidents.length).toBe(1);
    });

    it('CONCURRENCY: should handle simultaneous concurrent promotion requests and create exactly one incident', async () => {
      // Create a fresh candidate specifically for concurrency test
      const event = await eventRepo.save(
        eventRepo.create({
          eventType: 'SUSPICIOUS_PROCESS',
          severity: EventSeverity.CRITICAL,
          sourceIp: '198.51.100.95',
          targetUser: 'concurrent-user',
          eventTimestamp: new Date(),
        }),
      );
      const { candidate: concurrentCandidate } = await correlationService.processEvent(event);

      // Fire 3 simultaneous promotion requests concurrently
      const [res1, res2, res3] = await Promise.all([
        request(app.getHttpServer())
          .post(`/api/v1/correlation/candidates/${concurrentCandidate.id}/promote`)
          .set('Authorization', `Bearer ${adminToken}`),
        request(app.getHttpServer())
          .post(`/api/v1/correlation/candidates/${concurrentCandidate.id}/promote`)
          .set('Authorization', `Bearer ${adminToken}`),
        request(app.getHttpServer())
          .post(`/api/v1/correlation/candidates/${concurrentCandidate.id}/promote`)
          .set('Authorization', `Bearer ${adminToken}`),
      ]);

      // All 3 succeed with 201
      expect(res1.status).toBe(201);
      expect(res2.status).toBe(201);
      expect(res3.status).toBe(201);

      // All 3 share the EXACT SAME promoted incident ID
      expect(res1.body.incidentId).toBeDefined();
      expect(res2.body.incidentId).toBe(res1.body.incidentId);
      expect(res3.body.incidentId).toBe(res1.body.incidentId);

      // Strictly verify only ONE incident exists for this candidate
      const count = await incidentRepo.count({ where: { id: res1.body.incidentId } });
      expect(count).toBe(1);
    });

    it('should dismiss candidate incident with analyst reason', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${candidateToPromote.id}/dismiss`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Verified benign admin maintenance script' });

      expect(res.status).toBe(201);
      expect(res.body.status).toBe(CandidateIncidentStatus.DISMISSED);
      expect(res.body.dismissedReason).toBe('Verified benign admin maintenance script');
    });

    it('should reject promoting an already dismissed candidate incident with 400 Bad Request', async () => {
      // First dismiss
      await correlationService.dismissCandidate(
        candidateToPromote.id,
        'False positive test',
        '99999999-9999-9999-9999-999999999999',
      );

      // Attempt to promote
      const res = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${candidateToPromote.id}/promote`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Cannot promote a dismissed candidate');
    });
  });

  describe('4. Authorization, RBAC & API Contracts', () => {
    let testCandidateId: string;

    beforeAll(async () => {
      const event = eventRepo.create({
        eventType: 'PORT_SCAN',
        severity: EventSeverity.MEDIUM,
        sourceIp: '198.51.100.88',
        rawPayload: { ports: [22, 80, 443, 3389] },
        normalizedDetails: {},
        eventTimestamp: new Date(),
      });
      const saved = await eventRepo.save(event);
      const res = await correlationService.processEvent(saved);
      testCandidateId = res.candidate.id;
    });

    it('should allow READ_ONLY_AUDITOR to query candidate incidents', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/correlation/candidates')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data).toBeDefined();
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.total).toBeGreaterThanOrEqual(1);
    });

    it('should deny READ_ONLY_AUDITOR from promoting candidate incidents with 403 Forbidden', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/correlation/candidates/${testCandidateId}/promote`)
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(403);
    });

    it('should deny unauthenticated requests with 401 Unauthorized', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/correlation/candidates');

      expect(res.status).toBe(401);
    });

    it('should validate query filters (pagination, status, minConfidence)', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/correlation/candidates?status=CANDIDATE&limit=10&minConfidence=0.1')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBeLessThanOrEqual(10);
      res.body.data.forEach((c: any) => {
        expect(c.status).toBe(CandidateIncidentStatus.CANDIDATE);
        expect(c.confidenceScore).toBeGreaterThanOrEqual(0.1);
      });
    });

    it('should evaluate pair of events in explainable sandbox endpoint', async () => {
      const eventA = await eventRepo.save(
        eventRepo.create({
          eventType: 'AUTH_FAILURE',
          sourceIp: '10.0.0.99',
          targetUser: 'sysadmin',
          eventTimestamp: new Date(),
        }),
      );
      const eventB = await eventRepo.save(
        eventRepo.create({
          eventType: 'PRIVILEGE_ESCALATION',
          sourceIp: '10.0.0.99',
          targetUser: 'sysadmin',
          eventTimestamp: new Date(),
        }),
      );

      const res = await request(app.getHttpServer())
        .post('/api/v1/correlation/evaluate-pair')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ eventAId: eventA.id, eventBId: eventB.id });

      expect(res.status).toBe(201);
      expect(res.body.isCorrelated).toBe(true);
      expect(res.body.score).toBeGreaterThanOrEqual(0.5);
      expect(res.body.factors.length).toBeGreaterThan(0);
      expect(res.body.explanation).toBeDefined();
    });
  });
});
