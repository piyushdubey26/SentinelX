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

  // 2. Read migration and seed SQL
  const migrationSqlPath = path.resolve(__dirname, '../../database/migrations/001_initial_soc_schema.sql');
  const seedSqlPath = path.resolve(__dirname, '../../database/seeds/001_initial_roles_and_admin.sql');

  const migrationSql = fs.readFileSync(migrationSqlPath, 'utf8');
  const seedSql = fs.readFileSync(seedSqlPath, 'utf8');

  // 3. Apply schema and seeds to both sentinelx and sentinelx_test
  for (const db of dbs) {
    console.log(`[SETUP-DB] Applying schema & seeds to ${db}...`);
    const dbClient = new Client({ host, port, user, password, database: db, ssl });
    await dbClient.connect();
    await dbClient.query(migrationSql);
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
