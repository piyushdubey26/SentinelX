import { MigrationInterface, QueryRunner } from 'typeorm';
import * as fs from 'fs';
import * as path from 'path';

export class InitialSocSchema1712900000000 implements MigrationInterface {
  name = 'InitialSocSchema1712900000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    const upSqlPath = path.resolve(__dirname, '../../../../database/migrations/001_initial_soc_schema.sql');
    const sql = fs.readFileSync(upSqlPath, 'utf8');
    await queryRunner.query(sql);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const downSqlPath = path.resolve(__dirname, '../../../../database/migrations/001_initial_soc_schema_down.sql');
    const sql = fs.readFileSync(downSqlPath, 'utf8');
    await queryRunner.query(sql);
  }
}
