import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AuditService } from './audit.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';

@Controller('audit')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('logs')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.READ_ONLY_AUDITOR)
  async getLogs(
    @Query('limit') limit = '50',
    @Query('offset') offset = '0',
  ) {
    return this.auditService.getRecentLogs(parseInt(limit, 10), parseInt(offset, 10));
  }
}
