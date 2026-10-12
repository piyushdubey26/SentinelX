import { IsString, IsNotEmpty, MaxLength, MinLength, IsOptional, IsEnum, IsNumber, Min, Max, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';
import { CandidateIncidentStatus } from '../correlation.types';

export class DismissCandidateDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(500)
  reason!: string;
}

export class QueryCandidatesDto {
  @IsOptional()
  @IsEnum(CandidateIncidentStatus)
  status?: CandidateIncidentStatus;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0.0)
  @Max(1.0)
  minConfidence?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 20;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  offset?: number = 0;
}

export class EvaluatePairDto {
  @IsUUID()
  @IsNotEmpty()
  eventAId!: string;

  @IsUUID()
  @IsNotEmpty()
  eventBId!: string;
}
