import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  UseGuards,
  Ip,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CorrelationService } from './correlation.service';
import {
  DismissCandidateDto,
  QueryCandidatesDto,
  EvaluatePairDto,
} from './dto/candidate-action.dto';
import { SecurityEvent } from '../events/entities/security-event.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@Controller('correlation')
@UseGuards(JwtAuthGuard, RolesGuard)
export class CorrelationController {
  constructor(
    private readonly correlationService: CorrelationService,
    @InjectRepository(SecurityEvent)
    private readonly eventRepo: Repository<SecurityEvent>,
  ) {}

  @Get('candidates')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getCandidates(@Query() query: QueryCandidatesDto) {
    return this.correlationService.findAllCandidates({
      status: query.status,
      minConfidence: query.minConfidence,
      limit: query.limit,
      offset: query.offset,
    });
  }

  @Get('candidates/:id')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getCandidate(@Param('id') id: string) {
    return this.correlationService.findById(id);
  }

  @Post('candidates/:id/promote')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async promoteCandidate(
    @Param('id') id: string,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.correlationService.promoteCandidate(id, user?.id, ip);
  }

  @Post('candidates/:id/dismiss')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async dismissCandidate(
    @Param('id') id: string,
    @Body() dto: DismissCandidateDto,
    @CurrentUser() user: any,
    @Ip() ip: string,
  ) {
    return this.correlationService.dismissCandidate(id, dto.reason, user?.id, ip);
  }

  @Post('evaluate-pair')
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async evaluatePair(@Body() dto: EvaluatePairDto) {
    const eventA = await this.eventRepo.findOne({ where: { id: dto.eventAId } });
    if (!eventA) {
      throw new NotFoundException(`Event A with id ${dto.eventAId} not found`);
    }

    const eventB = await this.eventRepo.findOne({ where: { id: dto.eventBId } });
    if (!eventB) {
      throw new NotFoundException(`Event B with id ${dto.eventBId} not found`);
    }

    return this.correlationService.getEngine().compareEvents(eventA, eventB);
  }
}
