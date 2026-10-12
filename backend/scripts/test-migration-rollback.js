const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

async function testMigrationAndRollback() {
  const host = process.env.DB_HOST || 'localhost';
  const port = parseInt(process.env.DB_PORT || '5432', 10);
  const user = process.env.DB_USERNAME || 'piyushdubey';
  const password = process.env.DB_PASSWORD || '';
  const database = 'sentinelx_test';

  console.log(`[TEST-MIGRATION] Connecting to ${database}...`);
  const client = new Client({ host, port, user, password, database });
  await client.connect();

  const upSqlPath = path.resolve(__dirname, '../../database/migrations/003_event_correlation_and_candidate_incidents.sql');
  const downSqlPath = path.resolve(__dirname, '../../database/migrations/003_event_correlation_and_candidate_incidents_down.sql');

  const upSql = fs.readFileSync(upSqlPath, 'utf8');
  const downSql = fs.readFileSync(downSqlPath, 'utf8');

  // Verify candidate_incidents table exists
  let check = await client.query(`SELECT table_name FROM information_schema.tables WHERE table_name = 'candidate_incidents'`);
  console.log(`[TEST-MIGRATION] Table candidate_incidents exists before rollback: ${check.rowCount === 1}`);
  if (check.rowCount !== 1) {
    throw new Error('candidate_incidents should exist');
  }

  // Execute Down Migration
  console.log('[TEST-MIGRATION] Executing down migration (rollback)...');
  await client.query(downSql);

  check = await client.query(`SELECT table_name FROM information_schema.tables WHERE table_name = 'candidate_incidents'`);
  console.log(`[TEST-MIGRATION] Table candidate_incidents exists after rollback: ${check.rowCount === 1}`);
  if (check.rowCount !== 0) {
    throw new Error('candidate_incidents should NOT exist after rollback');
  }

  // Verify other tables (security_events, users) are untouched
  const existingTablesCheck = await client.query(`SELECT table_name FROM information_schema.tables WHERE table_name IN ('security_events', 'users', 'incidents')`);
  console.log(`[TEST-MIGRATION] Core tables intact after rollback: ${existingTablesCheck.rowCount === 3}`);
  if (existingTablesCheck.rowCount !== 3) {
    throw new Error('Core tables were unexpectedly affected by rollback');
  }

  // Re-apply Up Migration
  console.log('[TEST-MIGRATION] Re-applying up migration...');
  await client.query(upSql);

  check = await client.query(`SELECT table_name FROM information_schema.tables WHERE table_name = 'candidate_incidents'`);
  console.log(`[TEST-MIGRATION] Table candidate_incidents exists after re-applying up migration: ${check.rowCount === 1}`);
  if (check.rowCount !== 1) {
    throw new Error('candidate_incidents should exist after re-applying up migration');
  }

  await client.end();
  console.log('[TEST-MIGRATION] PASS: Migration and rollback verified successfully on test database.');
}

testMigrationAndRollback().catch((err) => {
  console.error('[TEST-MIGRATION] FAIL:', err);
  process.exit(1);
});
