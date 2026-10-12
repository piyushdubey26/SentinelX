import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

describe('HealthController', () => {
  let controller: HealthController;

  const mockHealthService = {
    check: jest.fn().mockResolvedValue({
      status: 'healthy',
      timestamp: '2026-10-12T00:00:00.000Z',
      uptimeSeconds: 42,
      environment: 'test',
      database: {
        connected: true,
        databaseName: 'sentinelx_test',
      },
      version: '0.1.0',
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        {
          provide: HealthService,
          useValue: mockHealthService,
        },
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should return health status', async () => {
    const result = await controller.getHealth();
    expect(result.status).toBe('healthy');
    expect(result.database.connected).toBe(true);
  });
});
