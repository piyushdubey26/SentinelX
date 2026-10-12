import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { databaseConfig } from './config/database.config';
import { CommonModule } from './common/common.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { AssetsModule } from './assets/assets.module';
import { EventsModule } from './events/events.module';
import { DetectionsModule } from './detections/detections.module';
import { IncidentsModule } from './incidents/incidents.module';
import { RiskModule } from './risk/risk.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig],
      envFilePath: ['.env', '../.env'],
    }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => config.get('database')!,
    }),
    CommonModule,
    AuthModule,
    UsersModule,
    AssetsModule,
    EventsModule,
    DetectionsModule,
    IncidentsModule,
    RiskModule,
    AuditModule,
  ],
})
export class AppModule {}
