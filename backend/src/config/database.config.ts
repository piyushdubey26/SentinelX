import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const databaseConfig = registerAs(
  'database',
  (): TypeOrmModuleOptions => ({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'piyushdubey',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'sentinelx',
    entities: [__dirname + '/../**/*.entity{.ts,.js}'],
    // CRITICAL: synchronize must remain FALSE in all environments to enforce migration safety
    synchronize: false,
    logging: process.env.DB_LOGGING === 'true',
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  }),
);
