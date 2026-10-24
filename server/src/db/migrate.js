/**
 * TrustVault Version-Controlled SQL Migration Runner
 * Executes migrations sequentially inside database transactions.
 */

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const dbUrl = process.env.DATABASE_URL || process.env.SUPABASE_DB_URL;

async function runMigrations() {
  console.log('================================================================');
  console.log('🚀 TrustVault: Version-Controlled SQL Migration Runner');
  console.log('================================================================');

  if (!dbUrl) {
    console.log('ℹ️  No DATABASE_URL or SUPABASE_DB_URL provided in .env.');
    console.log('ℹ️  SQL migration files are located in:');
    console.log('    • server/src/db/migrations/');
    console.log('    • supabase/migrations/');
    console.log('ℹ️  You can execute them directly in the Supabase SQL Editor or via:');
    console.log('    DATABASE_URL="postgres://..." npm run migrate');
    return;
  }

  const client = new Client({
    connectionString: dbUrl,
    ssl: dbUrl.includes('localhost') ? false : { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    console.log('Connected to PostgreSQL database.');

    // 1. Create schema_migrations table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // 2. Fetch already applied migrations
    const res = await client.query('SELECT version FROM public.schema_migrations;');
    const applied = new Set(res.rows.map(r => r.version));

    // 3. Read migration files
    const migrationsDir = path.resolve(__dirname, 'migrations');
    const files = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      if (applied.has(file)) {
        console.log(`✓ Migration ${file} (already applied)`);
        continue;
      }

      console.log(`⏳ Applying migration: ${file}...`);
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');

      // Execute within transaction
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO public.schema_migrations (version) VALUES ($1);', [file]);
        await client.query('COMMIT');
        console.log(`✅ Successfully applied: ${file}`);
      } catch (migrationErr) {
        await client.query('ROLLBACK');
        console.error(`❌ Migration failed in ${file}. Rolled back transaction.`);
        throw migrationErr;
      }
    }

    console.log('================================================================');
    console.log('🎉 All database migrations applied successfully!');
    console.log('================================================================');
  } catch (err) {
    console.error('Migration runner error:', err.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

if (require.main === module) {
  runMigrations();
}

module.exports = runMigrations;
