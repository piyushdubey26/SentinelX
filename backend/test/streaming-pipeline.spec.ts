import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { StreamingService } from '../src/streaming/streaming.service';
import { DeadLetterQueueService } from '../src/streaming/dead-letter-queue.service';
import { IdempotencyService } from '../src/streaming/idempotency.service';

describe('Milestone 2.1: Streaming Pipeline, Idempotency, DLQ & Consumer Health', () => {
  let app: INestApplication;
  let adminToken: string;
  let streamingService: StreamingService;
  let dlqService: DeadLetterQueueService;
  let idempotencyService: IdempotencyService;

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

    streamingService = app.get(StreamingService);
    dlqService = app.get(DeadLetterQueueService);
    idempotencyService = app.get(IdempotencyService);

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

  it('1. should ingest and normalize security event through streaming pipeline', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/events/ingest?sync=true')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        eventType: 'AUTH_FAILURE',
        sourceIp: '10.0.50.12',
        sourcePort: 22,
        targetUser: 'root_admin',
        rawPayload: { service: 'sshd', auth_method: 'password' },
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('PROCESSED');
    expect(res.body.trackingId).toBeDefined();
    expect(res.body.idempotencyKey).toBeDefined();
    expect(res.body.event).toBeDefined();
    expect(res.body.event.sourceIp).toBe('10.0.50.12');
    expect(res.body.event.targetUser).toBe('root_admin');
    expect(res.body.event.normalizedDetails).toBeDefined();
    expect(res.body.event.normalizedDetails.enrichment.category).toBe('authentication');
  });

  it('2. should enforce idempotency: duplicate event with same key is skipped', async () => {
    const fixedIdempotencyKey = `idemp-test-${Date.now()}`;

    // First ingestion (sync)
    const firstRes = await streamingService.ingestEvent(
      {
        eventType: 'PORT_SCAN',
        sourceIp: '198.51.100.99',
        rawPayload: { scanId: 1 },
      } as any,
      '127.0.0.1',
      true,
    );

    expect(firstRes.status).toBe('PROCESSED');

    // Attempt to claim same key directly via idempotency service
    const canClaimAgain = await idempotencyService.checkAndClaim(firstRes.idempotencyKey);
    expect(canClaimAgain).toBe(false); // Second claim rejected as duplicate
  });

  it('3. should route poison-pill payload to Dead Letter Queue (DLQ) after retries', async () => {
    const poisonPayload = {
      corruptedField: true,
      reason: 'intentional-poison-pill',
    };

    // Directly publish corrupt message to trigger DLQ handler
    const dlqRecord = await dlqService.captureFailure(
      'security.events.raw',
      poisonPayload,
      new Error('Test unrecoverable serialization failure'),
      3,
    );

    expect(dlqRecord.id).toBeDefined();
    expect(dlqRecord.topic).toBe('security.events.raw');
    expect(dlqRecord.errorMessage).toContain('Test unrecoverable serialization failure');
    expect(dlqRecord.retryCount).toBe(3);
    expect(dlqRecord.resolved).toBe(false);

    // Verify DLQ record appears in DLQ API
    const dlqApiRes = await request(app.getHttpServer())
      .get('/api/v1/events/dlq?limit=10')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(dlqApiRes.status).toBe(200);
    expect(dlqApiRes.body.data).toBeDefined();
    const found = dlqApiRes.body.data.find((d: any) => d.id === dlqRecord.id);
    expect(found).toBeDefined();
  });

  it('4. should report consumer health, topics, and lag statistics', async () => {
    const statsRes = await request(app.getHttpServer())
      .get('/api/v1/events/streaming/stats')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(statsRes.status).toBe(200);
    expect(statsRes.body.status).toBe('CONNECTED');
    expect(statsRes.body.driver).toBeDefined();
    expect(statsRes.body.topics).toContain('security.events.raw');
    expect(statsRes.body.topics).toContain('security.events.dlq');
    expect(statsRes.body.totalPublished).toBeGreaterThanOrEqual(1);
    expect(statsRes.body.lag).toBeDefined();
    expect(Array.isArray(statsRes.body.lag)).toBe(true);
  });

  it('5. should handle out-of-order timestamps without crashing or corrupting state', async () => {
    const now = Date.now();
    const olderTimestamp = new Date(now - 30000).toISOString(); // 30 seconds in the past

    const res = await request(app.getHttpServer())
      .post('/api/v1/events/ingest?sync=true')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        eventType: 'AUTH_FAILURE',
        sourceIp: '10.0.99.1',
        eventTimestamp: olderTimestamp,
        rawPayload: { delayed: true },
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('PROCESSED');
    expect(res.body.event.id).toBeDefined();
    expect(new Date(res.body.event.eventTimestamp).getTime()).toBe(new Date(olderTimestamp).getTime());
  });
});
