import { Controller, Post, Get, Body, Query, UseGuards, Ip } from '@nestjs/common';
import { EventsService } from './events.service';
import { IngestEventDto } from './dto/ingest-event.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RoleType } from '../users/entities/role.entity';
import { Throttle } from '@nestjs/throttler';

@Controller('events')
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  @Post('ingest')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(RoleType.ADMIN, RoleType.SECURITY_ENGINEER, RoleType.SOC_ANALYST)
  @Throttle({ default: { limit: process.env.NODE_ENV === 'test' ? 1000 : 120, ttl: 60000 } })
  async ingest(@Body() dto: IngestEventDto, @Ip() ip: string) {
    return this.eventsService.ingest(dto, ip);
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
