const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

async function setup() {
  const host = process.env.DB_HOST || 'localhost';
  const port = parseInt(process.env.DB_PORT || '5432', 10);
  const user = process.env.DB_USERNAME || 'piyushdubey';
  const password = process.env.DB_PASSWORD || '';
  const ssl = process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false;

  console.log(`[SETUP-DB] Connecting to PostgreSQL at ${host}:${port} as ${user}...`);

  // 1. Connect to default postgres DB to ensure sentinelx and sentinelx_test exist
  const rootClient = new Client({ host, port, user, password, database: 'postgres', ssl });
  await rootClient.connect();

  const dbs = ['sentinelx', 'sentinelx_test'];
  for (const db of dbs) {
    const checkRes = await rootClient.query(`SELECT 1 FROM pg_database WHERE datname = $1`, [db]);
    if (checkRes.rowCount === 0) {
      console.log(`[SETUP-DB] Creating database ${db}...`);
      await rootClient.query(`CREATE DATABASE "${db}"`);
    } else {
      console.log(`[SETUP-DB] Database ${db} already exists.`);
    }
  }
  await rootClient.end();

  // 2. Discover and sort migration SQL files
  const migrationsDir = path.resolve(__dirname, '../../database/migrations');
  const migrationFiles = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql') && !f.endsWith('_down.sql'))
    .sort();

  const seedSqlPath = path.resolve(__dirname, '../../database/seeds/001_initial_roles_and_admin.sql');
  const seedSql = fs.readFileSync(seedSqlPath, 'utf8');

  // 3. Apply all schema migrations and seeds to both sentinelx and sentinelx_test
  for (const db of dbs) {
    console.log(`[SETUP-DB] Applying schema migrations & seeds to ${db}...`);
    const dbClient = new Client({ host, port, user, password, database: db, ssl });
    await dbClient.connect();

    for (const mFile of migrationFiles) {
      console.log(`[SETUP-DB] -> Running migration ${mFile} on ${db}...`);
      const mSql = fs.readFileSync(path.join(migrationsDir, mFile), 'utf8');
      await dbClient.query(mSql);
    }

    console.log(`[SETUP-DB] -> Running seed on ${db}...`);
    await dbClient.query(seedSql);
    await dbClient.end();
    console.log(`[SETUP-DB] Completed setup for ${db}.`);
  }

  console.log('[SETUP-DB] Database initialization finished successfully.');
}

setup().catch((err) => {
  console.error('[SETUP-DB] Error initializing database:', err);
  process.exit(1);
});
