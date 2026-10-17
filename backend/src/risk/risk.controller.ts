import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { RiskScoringService } from './risk-scoring.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { IncidentStatus } from '../incidents/entities/incident.entity';

@Controller('risk')
@UseGuards(JwtAuthGuard, RolesGuard)
export class RiskController {
  constructor(private readonly riskService: RiskScoringService) {}

  /**
   * Retrieves Top-K risk-prioritized incidents using the O(N log K) Binary Heap algorithm.
   */
  @Get('incidents/prioritized')
  @Roles(
    RoleType.ADMIN,
    RoleType.SECURITY_ENGINEER,
    RoleType.SOC_ANALYST,
    RoleType.READ_ONLY_AUDITOR,
  )
  async getPrioritizedIncidents(
    @Query('limit') limit = '20',
    @Query('status') status?: IncidentStatus,
  ) {
    const parsedLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
    return this.riskService.getPrioritizedIncidents(parsedLimit, status);
  }

  /**
   * Retrieves an explainable risk breakdown and calculation audit trail for a specific incident.
   */
  @Get('incidents/:id/breakdown')
  @Roles(
    RoleType.ADMIN,
    RoleType.SECURITY_ENGINEER,
    RoleType.SOC_ANALYST,
    RoleType.READ_ONLY_AUDITOR,
  )
  async getIncidentRiskBreakdown(@Param('id') id: string) {
    const incident = await this.riskService.calculateAndPersistIncidentRisk(id);
    return {
      incidentId: incident.id,
      code: incident.code,
      riskScore: incident.riskScore,
      riskTier: incident.riskTier,
      riskFactors: incident.riskFactors,
    };
  }

  /**
   * Recalculates and persists risk score for a single incident.
   */
  @Post('incidents/:id/recalculate')
  @HttpCode(HttpStatus.OK)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async recalculateIncidentRisk(@Param('id') id: string) {
    const incident = await this.riskService.calculateAndPersistIncidentRisk(id);
    return {
      message: `Risk score successfully recalculated for incident ${incident.code}.`,
      incidentId: incident.id,
      code: incident.code,
      riskScore: incident.riskScore,
      riskTier: incident.riskTier,
    };
  }

  /**
   * Recalculates risk scores across all open and investigating incidents.
   */
  @Post('recalculate-all')
  @HttpCode(HttpStatus.OK)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER)
  async recalculateAllActive() {
    return this.riskService.recalculateAllOpenIncidents();
  }

  /**
   * Returns current scoring configuration and weights.
   */
  @Get('config')
  @Roles(
    RoleType.ADMIN,
    RoleType.SECURITY_ENGINEER,
    RoleType.SOC_ANALYST,
    RoleType.READ_ONLY_AUDITOR,
  )
  getConfig() {
    return this.riskService.getConfig();
  }
}
