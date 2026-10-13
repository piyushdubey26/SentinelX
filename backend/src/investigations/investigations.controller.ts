import { Controller, Get, Param, Query, UseGuards, Ip } from '@nestjs/common';
import { InvestigationsService } from './investigations.service';
import {
  GetIncidentGraphQueryDto,
  FindPathsQueryDto,
  BlastRadiusQueryDto,
} from './dto/investigation-query.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@Controller('investigations')
@UseGuards(JwtAuthGuard, RolesGuard)
export class InvestigationsController {
  constructor(private readonly investigationsService: InvestigationsService) {}

  @Get('incident/:id/graph')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getIncidentGraph(
    @Param('id') id: string,
    @Query() query: GetIncidentGraphQueryDto,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.investigationsService.getIncidentGraph(id, query, user?.id, ip);
  }

  @Get('incident/:id/paths')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async findIncidentPaths(
    @Param('id') id: string,
    @Query() query: FindPathsQueryDto,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.investigationsService.findIncidentPaths(id, query, user?.id, ip);
  }

  @Get('incident/:id/blast-radius')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getIncidentBlastRadius(
    @Param('id') id: string,
    @Query() query: BlastRadiusQueryDto,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.investigationsService.getIncidentBlastRadius(id, query, user?.id, ip);
  }

  @Get('incident/:id/cycles')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getIncidentCycles(
    @Param('id') id: string,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.investigationsService.getIncidentCycles(id, user?.id, ip);
  }
}
