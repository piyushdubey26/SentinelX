import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { DetectionsService } from './detections.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';

@Controller('detections')
@UseGuards(JwtAuthGuard, RolesGuard)
export class DetectionsController {
  constructor(private readonly detectionsService: DetectionsService) {}

  @Get()
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getDetections(
    @Query('limit') limit = '20',
    @Query('offset') offset = '0',
  ) {
    return this.detectionsService.findAll(parseInt(limit, 10), parseInt(offset, 10));
  }
}
