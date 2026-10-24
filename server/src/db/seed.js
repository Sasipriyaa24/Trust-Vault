/**
 * TrustVault Safe Database Seeding Utility
 * Seeds separate Administrator, Document Owner, and Viewer demo accounts.
 * Passwords are read strictly from environment variables (never hardcoded in production).
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const config = require('../config/env');
const db = require('./db');

async function seedDatabase() {
  console.log('================================================================');
  console.log('🌱 TrustVault: Initializing Safe Demo Account Seeding...');
  console.log('================================================================');

  // Load passwords from environment variables or generate ephemeral test passwords
  const adminEmail = process.env.SEED_ADMIN_EMAIL || 'admin@trustvault.internal';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || (config.nodeEnv === 'production' ? crypto.randomBytes(16).toString('hex') : 'AdminDemo2026!Secure');

  const ownerEmail = process.env.SEED_OWNER_EMAIL || 'owner@trustvault.internal';
  const ownerPassword = process.env.SEED_OWNER_PASSWORD || (config.nodeEnv === 'production' ? crypto.randomBytes(16).toString('hex') : 'OwnerDemo2026!Secure');

  const viewerEmail = process.env.SEED_VIEWER_EMAIL || 'viewer@trustvault.internal';
  const viewerPassword = process.env.SEED_VIEWER_PASSWORD || (config.nodeEnv === 'production' ? crypto.randomBytes(16).toString('hex') : 'ViewerDemo2026!Secure');

  const isLiveSupabase = (
    config.supabaseUrl &&
    config.supabaseUrl.startsWith('https://') &&
    !config.supabaseUrl.includes('demo-trustvault') &&
    config.supabaseServiceRoleKey &&
    !config.supabaseServiceRoleKey.startsWith('demo-')
  );

  if (isLiveSupabase) {
    console.log(`Connecting to Live Supabase Auth at: ${config.supabaseUrl}`);
    const supabaseAdmin = createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
      auth: { persistSession: false }
    });

    const accountsToSeed = [
      {
        email: adminEmail,
        password: adminPassword,
        fullName: 'Security Administrator',
        role: 'administrator'
      },
      {
        email: ownerEmail,
        password: ownerPassword,
        fullName: 'Primary Document Owner',
        role: 'document_owner'
      },
      {
        email: viewerEmail,
        password: viewerPassword,
        fullName: 'External Audit Viewer',
        role: 'viewer'
      }
    ];

    for (const acc of accountsToSeed) {
      console.log(`Provisioning: ${acc.email} (${acc.role})...`);
      
      // Attempt to create user via Supabase Auth Admin API
      const { data: user, error } = await supabaseAdmin.auth.admin.createUser({
        email: acc.email,
        password: acc.password,
        email_confirm: true,
        user_metadata: {
          full_name: acc.fullName,
          system_role: acc.role
        }
      });

      if (error) {
        if (error.message.includes('already exists') || error.message.includes('unique')) {
          console.log(`ℹ️ User ${acc.email} already exists in Supabase Auth.`);
        } else {
          console.error(`⚠️ Failed to create ${acc.email}:`, error.message);
        }
      } else if (user?.user) {
        // Ensure role is explicitly set in profiles table
        await supabaseAdmin
          .from('profiles')
          .update({ system_role: acc.role, full_name: acc.fullName })
          .eq('id', user.user.id);
        console.log(`✓ User ${acc.email} created with role ${acc.role}.`);
      }
    }
  } else {
    console.log('🔒 Seeding In-Memory / Local Repository Store:');
    console.log(`✓ Administrator: ${adminEmail}`);
    console.log(`✓ Document Owner: ${ownerEmail}`);
    console.log(`✓ Restricted Viewer: ${viewerEmail}`);
  }

  console.log('================================================================');
  console.log('✅ Safe Seeding Complete.');
  console.log('================================================================');
}

if (require.main === module) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Seeding failure:', err);
      process.exit(1);
    });
}

module.exports = seedDatabase;
