import { Controller, Post, Get, Body, Query, UseGuards, Ip } from '@nestjs/common';
import { EventsService } from './events.service';
import { IngestEventDto } from './dto/ingest-event.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { Throttle } from '@nestjs/throttler';
import { DeadLetterQueueService } from '../streaming/dead-letter-queue.service';
import { StreamingService } from '../streaming/streaming.service';

@Controller('events')
export class EventsController {
  constructor(
    private readonly eventsService: EventsService,
    private readonly dlqService: DeadLetterQueueService,
    private readonly streamingService: StreamingService,
  ) {}

  @Post('ingest')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  @Throttle({ default: { limit: process.env.NODE_ENV === 'test' ? 1000 : 120, ttl: 60000 } })
  async ingest(
    @Body() dto: IngestEventDto,
    @Ip() ip: string,
    @Query('sync') sync?: string,
  ) {
    const isSync = sync !== 'false';
    return this.eventsService.ingest(dto, ip, isSync);
  }

  @Get('dlq')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER)
  async getDeadLetterQueue(
    @Query('limit') limit = '50',
    @Query('offset') offset = '0',
    @Query('resolved') resolved?: string,
  ) {
    const isResolved = resolved !== undefined ? resolved === 'true' : undefined;
    return this.dlqService.findAll(parseInt(limit, 10), parseInt(offset, 10), isResolved);
  }

  @Get('streaming/stats')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  async getStreamingStats() {
    return this.streamingService.getStats();
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST, RoleType.READ_ONLY_AUDITOR)
  async getEvents(
    @Query('limit') limit = '50',
    @Query('offset') offset = '0',
  ) {
    return this.eventsService.findAll(parseInt(limit, 10), parseInt(offset, 10));
  }
}
