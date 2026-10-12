import { Controller, Get } from '@nestjs/common';
import { HealthService, HealthCheckResponse } from './health.service';

@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  async getHealth(): Promise<HealthCheckResponse> {
    return this.healthService.check();
  }
}
