import { IsString, IsOptional, IsInt, Min, Max, IsBoolean, IsEnum } from 'class-validator';
import { Type, Transform } from 'class-transformer';
import { GraphNodeType } from '../graph/graph.types';

export class GetIncidentGraphQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(5)
  maxHops: number = 2;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(168) // Max 7 days
  timeWindowHours: number = 24;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(500)
  limit: number = 100;

  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  @IsBoolean()
  includeEvents: boolean = true;
}

export class FindPathsQueryDto {
  @IsString()
  sourceId!: string;

  @IsString()
  targetId!: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10)
  maxDepth: number = 4;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10)
  maxPaths: number = 5;
}

export class BlastRadiusQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(4)
  maxHops: number = 2;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(168)
  timeWindowHours: number = 24;
}

export class GetEntityGraphQueryDto {
  @IsEnum(GraphNodeType)
  entityType!: GraphNodeType;

  @IsString()
  entityValue!: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(5)
  maxHops: number = 2;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(168)
  timeWindowHours: number = 24;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(500)
  limit: number = 100;
}
