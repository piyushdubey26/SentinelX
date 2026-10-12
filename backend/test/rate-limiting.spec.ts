import { Controller, Get, INestApplication } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import { ThrottlerGuard, ThrottlerModule, Throttle } from '@nestjs/throttler';
import * as request from 'supertest';

@Controller('test-security')
class SecurityTestController {
  @Get('throttled-endpoint')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  testEndpoint() {
    return { status: 'ALLOWED' };
  }
}

describe('Security Controls: Rate Limiting & Denial of Service Protection', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot([
          {
            ttl: 60000,
            limit: 10,
          },
        ]),
      ],
      controllers: [SecurityTestController],
      providers: [
        {
          provide: APP_GUARD,
          useClass: ThrottlerGuard,
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('1. should allow requests within the rate limit (limit = 3)', async () => {
    for (let i = 1; i <= 3; i++) {
      const response = await request(app.getHttpServer()).get('/test-security/throttled-endpoint');
      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ALLOWED');
    }
  });

  it('2. should reject the 4th request with HTTP 429 Too Many Requests', async () => {
    const response = await request(app.getHttpServer()).get('/test-security/throttled-endpoint');
    expect(response.status).toBe(429);
    expect(response.body.message).toContain('ThrottlerException: Too Many Requests');
  });
});
