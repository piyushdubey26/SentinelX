import { Controller, Get, Patch, Param, Body, Query, UseGuards, Ip } from '@nestjs/common';
import { IncidentsService } from './incidents.service';
import { UpdateIncidentStatusDto } from './dto/update-incident-status.dto';
import { IncidentStatus } from './entities/incident.entity';
import { EventSeverity } from '../events/entities/security-event.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@Controller('incidents')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @Get()
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getIncidents(
    @Query('status') status?: IncidentStatus,
    @Query('severity') severity?: EventSeverity,
    @Query('limit') limit = '20',
    @Query('offset') offset = '0',
    @Query('sortBy') sortBy?: 'riskScore' | 'createdAt',
    @Query('sortOrder') sortOrder?: 'ASC' | 'DESC',
  ) {
    return this.incidentsService.findAll({
      status,
      severity,
      limit: parseInt(limit, 10),
      offset: parseInt(offset, 10),
      sortBy,
      sortOrder,
    });
  }

  @Get('metrics')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getMetrics() {
    return this.incidentsService.getCounts();
  }

  @Get(':id')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getIncident(@Param('id') id: string) {
    return this.incidentsService.findById(id);
  }

  @Patch(':id/status')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async updateStatus(
    @Param('id') id: string,
    @Body() dto: UpdateIncidentStatusDto,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.incidentsService.updateStatus(id, dto.status, user.id, ip);
  }
}
