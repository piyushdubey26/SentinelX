import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Milestone 1.3: Authentication, RBAC & Security Integration Tests', () => {
  let app: INestApplication;
  let adminToken: string;
  let analystToken: string;

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
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('1. should reject login with invalid credentials with 401 Unauthorized', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({
        email: 'admin@sentinelx.local',
        password: 'WrongPassword999!',
      });

    expect(response.status).toBe(401);
    expect(response.body.message).toBe('Invalid email or password');
  });

  it('2. should reject login with malformed payload (validation failure)', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({
        email: 'not-an-email',
        password: '123',
      });

    expect(response.status).toBe(400);
  });

  it('3. should successfully log in admin user and issue JWT bearer token', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({
        email: 'admin@sentinelx.local',
        password: 'AdminPassword123!',
      });

    expect(response.status).toBe(201);
    expect(response.body.accessToken).toBeDefined();
    expect(response.body.tokenType).toBe('Bearer');
    expect(response.body.user.email).toBe('admin@sentinelx.local');
    expect(response.body.user.role).toBe('ADMIN');
    adminToken = response.body.accessToken;
  });

  it('4. should successfully log in SOC analyst user', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({
        email: 'analyst@sentinelx.local',
        password: 'AnalystPassword123!',
      });

    expect(response.status).toBe(201);
    expect(response.body.accessToken).toBeDefined();
    expect(response.body.user.role).toBe('SOC_ANALYST');
    analystToken = response.body.accessToken;
  });

  it('5. should deny access to protected profile endpoint without token (401)', async () => {
    const response = await request(app.getHttpServer()).get('/api/v1/auth/me');
    expect(response.status).toBe(401);
  });

  it('6. should allow access to profile endpoint with valid JWT token (200)', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(response.status).toBe(200);
    expect(response.body.email).toBe('admin@sentinelx.local');
    expect(response.body.role).toBe('ADMIN');
  });

  it('7. should DENY SOC Analyst from accessing Admin-only endpoint (403 Forbidden)', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${analystToken}`);

    expect(response.status).toBe(403);
    expect(response.body.message).toContain('Access denied');
  });

  it('8. should ALLOW Admin to access Admin-only endpoint (200 OK)', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
    expect(response.body.length).toBeGreaterThanOrEqual(2);
    // Verify passwordHash is never leaked in user responses
    expect(response.body[0].passwordHash).toBeUndefined();
  });

  it('9. should verify audit log recorded login actions without sensitive data', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/audit/logs?limit=10')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(response.status).toBe(200);
    expect(response.body.data).toBeDefined();
    expect(response.body.total).toBeGreaterThanOrEqual(1);

    // Verify sanitization: no password in details
    for (const log of response.body.data) {
      if (log.details) {
        expect(log.details.password).toBeUndefined();
        expect(log.details.passwordHash).toBeUndefined();
      }
    }
  });
});
