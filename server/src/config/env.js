const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  supabaseUrl: process.env.SUPABASE_URL || 'https://demo-trustvault.supabase.co',
  supabaseAnonKey: process.env.SUPABASE_ANON_KEY || 'demo-anon-key',
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || 'demo-service-role-key',
  supabaseJwtSecret: process.env.SUPABASE_JWT_SECRET || 'trustvault-super-secure-jwt-signing-secret-2026',
  auditHmacSecret: process.env.AUDIT_HMAC_SECRET || 'trustvault-audit-tamper-evident-hmac-secret-key-35percent',
  storageBucket: process.env.STORAGE_BUCKET_NAME || 'trustvault-docs',
  maxFileSizeBytes: 10 * 1024 * 1024, // 10MB strict limit
};

module.exports = config;
