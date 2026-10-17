import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AppModule } from '../src/app.module';
import { Incident, IncidentStatus } from '../src/incidents/entities/incident.entity';
import { Asset, AssetCriticality, AssetEnvironment } from '../src/assets/entities/asset.entity';
import { EventSeverity } from '../src/events/entities/security-event.entity';
import { AuditLog } from '../src/audit/entities/audit-log.entity';

describe('Milestone 2.4 - Risk Scoring & Prioritization API Integration', () => {
  let app: INestApplication;
  let incidentRepo: Repository<Incident>;
  let assetRepo: Repository<Asset>;
  let auditRepo: Repository<AuditLog>;

  let adminToken: string;
  let auditorToken: string;

  let testAssetCrit: Asset;
  let testAssetLow: Asset;
  let highRiskIncident: Incident;
  let lowRiskIncident: Incident;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();

    incidentRepo = app.get<Repository<Incident>>(getRepositoryToken(Incident));
    assetRepo = app.get<Repository<Asset>>(getRepositoryToken(Asset));
    auditRepo = app.get<Repository<AuditLog>>(getRepositoryToken(AuditLog));

    // Admin login
    const adminLoginRes = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'admin@sentinelx.local', password: 'AdminPassword123!' });
    adminToken = adminLoginRes.body.accessToken;

    // Auditor login
    const auditorLoginRes = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'auditor@sentinelx.local', password: 'AdminPassword123!' });
    auditorToken = auditorLoginRes.body.accessToken;

    // Clean up any conflicting records
    await incidentRepo.delete({ code: 'INC-RISK-TEST-HIGH' });
    await incidentRepo.delete({ code: 'INC-RISK-TEST-LOW' });
    await assetRepo.delete({ ipAddress: '198.51.100.88' });
    await assetRepo.delete({ ipAddress: '198.51.100.89' });

    // Seed test assets
    testAssetCrit = await assetRepo.save(
      assetRepo.create({
        hostname: 'core-db-prod.internal',
        ipAddress: '198.51.100.88',
        criticality: AssetCriticality.CRITICAL,
        environment: AssetEnvironment.PRODUCTION,
      }),
    );

    testAssetLow = await assetRepo.save(
      assetRepo.create({
        hostname: 'dev-sandbox-01.internal',
        ipAddress: '198.51.100.89',
        criticality: AssetCriticality.LOW,
        environment: AssetEnvironment.DEVELOPMENT,
      }),
    );

    const detectionRepo = app.get<Repository<any>>(getRepositoryToken(require('../src/detections/entities/detection.entity').Detection));
    const testDetection = await detectionRepo.save(
      detectionRepo.create({
        ruleId: 'RULE-BRUTE-FORCE-SQL',
        ruleName: 'Brute Force SQL Injection Attempt',
        severity: EventSeverity.CRITICAL,
        sourceIp: '198.51.100.88',
        triggerCount: 35,
        timeWindowSeconds: 60,
      }),
    );

    // Seed test incidents
    highRiskIncident = await incidentRepo.save(
      incidentRepo.create({
        code: 'INC-RISK-TEST-HIGH',
        title: 'Severe Database Infiltration Attempt',
        summary: 'Targeting core production database asset',
        severity: EventSeverity.CRITICAL,
        status: IncidentStatus.OPEN,
        sourceIp: '198.51.100.88',
        detectionId: testDetection.id,
        riskScore: 0.00,
        riskTier: 'LOW',
      }),
    );

    lowRiskIncident = await incidentRepo.save(
      incidentRepo.create({
        code: 'INC-RISK-TEST-LOW',
        title: 'Routine Dev Sandbox Ping Scan',
        summary: 'Low severity activity on development sandbox',
        severity: EventSeverity.LOW,
        status: IncidentStatus.OPEN,
        sourceIp: '198.51.100.89',
        riskScore: 0.00,
        riskTier: 'LOW',
      }),
    );
  });

  afterAll(async () => {
    if (highRiskIncident) await incidentRepo.delete({ id: highRiskIncident.id });
    if (lowRiskIncident) await incidentRepo.delete({ id: lowRiskIncident.id });
    if (testAssetCrit) await assetRepo.delete({ id: testAssetCrit.id });
    if (testAssetLow) await assetRepo.delete({ id: testAssetLow.id });
    await app.close();
  });

  describe('GET /api/v1/risk/config', () => {
    it('returns 200 with versioned scoring configuration', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/risk/config')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.version).toBe('1.0.0');
      expect(res.body.weights).toBeDefined();
      expect(res.body.weights.impactSeverityWeight).toBe(0.40);
    });

    it('returns 401 when unauthenticated', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/risk/config');
      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/v1/risk/incidents/:id/recalculate', () => {
    it('evaluates and persists risk score for a single incident', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/risk/incidents/${highRiskIncident.id}/recalculate`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.riskScore).toBeGreaterThanOrEqual(60.0);
      expect(res.body.riskTier).toMatch(/CRITICAL|HIGH/);

      // Verify DB persistence
      const reloaded = await incidentRepo.findOneBy({ id: highRiskIncident.id });
      expect(Number(reloaded?.riskScore)).toBeGreaterThanOrEqual(60.0);
      expect(reloaded?.riskTier).toBe(res.body.riskTier);
    });

    it('returns 403 Forbidden when called by READ_ONLY_AUDITOR', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/risk/incidents/${highRiskIncident.id}/recalculate`)
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(403);
    });

    it('returns 404 when incident does not exist', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/risk/incidents/00000000-0000-0000-0000-000000000000/recalculate')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/v1/risk/incidents/:id/breakdown', () => {
    it('returns explainable factor breakdown with transparent audit rationale', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/risk/incidents/${highRiskIncident.id}/breakdown`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.riskFactors).toBeDefined();
      expect(res.body.riskFactors.components.impact.score).toBeDefined();
      expect(res.body.riskFactors.components.confidence.score).toBeDefined();
      expect(res.body.riskFactors.components.recency.decayMultiplier).toBeDefined();
      expect(Array.isArray(res.body.riskFactors.explanation)).toBe(true);
      expect(res.body.riskFactors.explanation.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('POST /api/v1/risk/recalculate-all', () => {
    it('recalculates risk across all active open incidents in batch', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/risk/recalculate-all')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.evaluated).toBeGreaterThanOrEqual(2);
      expect(res.body.updated).toBeGreaterThanOrEqual(2);
    });
  });

  describe('GET /api/v1/risk/incidents/prioritized', () => {
    it('returns Top-K incidents ordered by riskScore DESC via Binary Heap', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/risk/incidents/prioritized?limit=10')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(2);

      // Verify descending priority order
      for (let i = 1; i < res.body.length; i++) {
        expect(res.body[i - 1].riskScore).toBeGreaterThanOrEqual(res.body[i].riskScore);
      }
    });

    it('allows READ_ONLY_AUDITOR to query prioritized incidents', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/risk/incidents/prioritized')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
    });
  });

  describe('Audit Logging Verification', () => {
    it('records immutable audit logs for risk evaluations', async () => {
      const audit = await auditRepo.findOne({
        where: {
          action: 'INCIDENT_RISK_EVALUATED',
          resourceId: highRiskIncident.id,
        },
        order: { timestamp: 'DESC' },
      });

      expect(audit).toBeDefined();
      expect(audit?.action).toBe('INCIDENT_RISK_EVALUATED');
      expect(audit?.details?.score).toBeDefined();
    });
  });
});
