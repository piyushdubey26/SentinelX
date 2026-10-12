import { IsEnum, IsNotEmpty, IsOptional, IsString, IsInt, Min, Max, IsObject } from 'class-validator';
import { EventSeverity } from '../entities/security-event.entity';

export class IngestEventDto {
  @IsString()
  @IsNotEmpty()
  eventType!: string;

  @IsEnum(EventSeverity)
  @IsOptional()
  severity?: EventSeverity;

  @IsString()
  @IsNotEmpty()
  sourceIp!: string;

  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  sourcePort?: number;

  @IsString()
  @IsOptional()
  destinationIp?: string;

  @IsString()
  @IsOptional()
  targetUser?: string;

  @IsObject()
  @IsOptional()
  rawPayload?: Record<string, any>;

  @IsString()
  @IsOptional()
  eventTimestamp?: string;
}
