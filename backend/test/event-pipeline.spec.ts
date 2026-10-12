import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Milestone 1.4: Event Ingestion & Deterministic Detection Pipeline', () => {
  let app: INestApplication;
  let adminToken: string;
  const attackIp = '198.51.100.42';
  const targetUser = 'victim_admin';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix('api/v1');
    await app.init();

    // Authenticate as Admin
    const loginRes = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({
        email: 'admin@sentinelx.local',
        password: 'AdminPassword123!',
      });
    adminToken = loginRes.body.accessToken;
    expect(adminToken).toBeDefined();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('1. should persist 4 failed login events without triggering detection', async () => {
    for (let i = 1; i <= 4; i++) {
      const res = await request(app.getHttpServer())
        .post('/api/v1/events/ingest')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          eventType: 'AUTH_FAILURE',
          sourceIp: attackIp,
          targetUser,
          rawPayload: { attempt: i, service: 'ssh' },
        });

      expect(res.status).toBe(201);
      expect(res.body.event.id).toBeDefined();
      expect(res.body.event.eventType).toBe('AUTH_FAILURE');
      expect(res.body.event.sourceIp).toBe(attackIp);
      expect(res.body.detectionCreated).toBe(false);
      expect(res.body.incidentCreated).toBe(false);
    }
  });

  it('2. should trigger detection and generate incident on 5th failed attempt', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/events/ingest')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        eventType: 'AUTH_FAILURE',
        sourceIp: attackIp,
        targetUser,
        rawPayload: { attempt: 5, service: 'ssh' },
      });

    expect(res.status).toBe(201);
    expect(res.body.event.id).toBeDefined();
    expect(res.body.detectionCreated).toBe(true);
    expect(res.body.incidentCreated).toBe(true);
  });

  it('3. should verify newly generated incident is queryable via Incidents API', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/incidents?limit=20')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
    expect(res.body.total).toBeGreaterThanOrEqual(1);

    const incident = res.body.data.find((inc: any) => inc.sourceIp === attackIp);
    expect(incident).toBeDefined();
    expect(incident.code).toMatch(/^INC-\d+/);
    expect(incident.status).toBe('OPEN');
    expect(incident.sourceIp).toBe(attackIp);
    expect(incident.detection).toBeDefined();
    expect(incident.detection.ruleId).toBe('RULE-BRUTE-FORCE-001');
    expect(incident.detection.triggerCount).toBe(5);
  });

  it('4. should update incident status with analyst audit log', async () => {
    const listRes = await request(app.getHttpServer())
      .get('/api/v1/incidents?limit=20')
      .set('Authorization', `Bearer ${adminToken}`);
    const incident = listRes.body.data.find((inc: any) => inc.sourceIp === attackIp);
    expect(incident).toBeDefined();
    const incidentId = incident.id;

    // Update status to INVESTIGATING
    const updateRes = await request(app.getHttpServer())
      .patch(`/api/v1/incidents/${incidentId}/status`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'INVESTIGATING' });

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.status).toBe('INVESTIGATING');

    // Verify audit log
    const auditRes = await request(app.getHttpServer())
      .get('/api/v1/audit/logs?limit=20')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(auditRes.status).toBe(200);
    const updateAudit = auditRes.body.data.find(
      (a: any) => a.action === 'INCIDENT_STATUS_UPDATED' && a.resourceId === incidentId,
    );
    expect(updateAudit).toBeDefined();
    expect(updateAudit.details.newStatus).toBe('INVESTIGATING');
  });

  it('5. should reject malformed event payloads with 400 Bad Request (input validation)', async () => {
    // Missing required sourceIp and eventType
    const malformedRes = await request(app.getHttpServer())
      .post('/api/v1/events/ingest')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        targetUser: 'attacker',
        sourcePort: 999999, // Invalid port > 65535
      });

    expect(malformedRes.status).toBe(400);
    expect(malformedRes.body.message).toBeDefined();
  });
});
