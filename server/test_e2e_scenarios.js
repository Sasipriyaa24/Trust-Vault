const http = require('http');

const BASE_URL = 'http://localhost:5000/api';

function request(method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${BASE_URL}${path}`);
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request(url, { method, headers }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runLiveVerification() {
  console.log('================================================================');
  console.log('🚀 TRUSTVAULT LIVE BACKEND & SECURITY VERIFICATION SUITE');
  console.log('================================================================\n');

  // 1. Health Check
  const health = await request('GET', '/health');
  console.log('1. Health Check:', health.status === 200 ? '✅ PASSED' : '❌ FAILED', health.body.service);

  // 2. Demo Switch to Document Owner
  const ownerSwitch = await request('POST', '/auth/demo-switch', { role: 'document_owner' });
  const ownerToken = ownerSwitch.body.token;
  const ownerUser = ownerSwitch.body.user;
  console.log('2. Authenticate Document Owner:', ownerToken ? '✅ SUCCESS' : '❌ FAILED', `(${ownerUser.email})`);

  // 3. Demo Switch to Viewer
  const viewerSwitch = await request('POST', '/auth/demo-switch', { role: 'viewer' });
  const viewerToken = viewerSwitch.body.token;
  const viewerUser = viewerSwitch.body.user;
  console.log('3. Authenticate Viewer Persona:', viewerToken ? '✅ SUCCESS' : '❌ FAILED', `(${viewerUser.email})`);

  // 4. Demo Switch to Administrator
  const adminSwitch = await request('POST', '/auth/demo-switch', { role: 'administrator' });
  const adminToken = adminSwitch.body.token;
  const adminUser = adminSwitch.body.user;
  console.log('4. Authenticate Administrator:', adminToken ? '✅ SUCCESS' : '❌ FAILED', `(${adminUser.email})`);

  // 5. Security Control: Viewer attempts to access Admin Audit Logs
  const viewerAdminAttempt = await request('GET', '/admin/audit-logs', null, viewerToken);
  console.log('5. Bypassed Frontend Test: Viewer queries /api/admin/audit-logs:');
  console.log(`   Response Status: ${viewerAdminAttempt.status} (Expected 403 Forbidden)`);
  console.log('   Security Outcome:', viewerAdminAttempt.status === 403 ? '🛡️ BLOCKED AS EXPECTED' : '❌ VULNERABLE');

  // 6. Security Control: Viewer attempts to upload document directly
  const viewerUploadAttempt = await request('POST', '/documents', { title: 'Malicious Ingest' }, viewerToken);
  console.log('6. Bypassed Frontend Test: Viewer posts /api/documents:');
  console.log(`   Response Status: ${viewerUploadAttempt.status} (Expected 400 or 403)`);
  console.log('   Security Outcome:', [400, 403].includes(viewerUploadAttempt.status) ? '🛡️ BLOCKED AS EXPECTED' : '❌ VULNERABLE');

  // 7. Admin queries audit logs
  const adminAuditQuery = await request('GET', '/admin/audit-logs', null, adminToken);
  console.log('7. Administrator queries /api/admin/audit-logs:');
  console.log(`   Status: ${adminAuditQuery.status}, Total logs recorded: ${adminAuditQuery.body.total}`);
  console.log('   Integrity:', adminAuditQuery.status === 200 ? '✅ SUCCESS' : '❌ FAILED');

  // 8. Cryptographic Hash Chain Verification
  const verifyRes = await request('GET', '/admin/audit-logs/verify', null, adminToken);
  console.log('8. Cryptographic Hash Chain Verification (/api/admin/audit-logs/verify):');
  console.log(`   Chain Valid: ${verifyRes.body.isValid}, Checked Records: ${verifyRes.body.checkedCount}`);
  console.log('   HMAC Integrity:', verifyRes.body.isValid ? '✅ CRYPTOGRAPHICALLY SOUND' : '❌ CHAIN BROKEN');

  // 9. Document Owner creates / views document
  const ownerDocs = await request('GET', '/documents', null, ownerToken);
  console.log('9. Document Owner listing documents (/api/documents):');
  console.log(`   Status: ${ownerDocs.status}, Accessible documents: ${ownerDocs.body.total}`);
  const firstDoc = ownerDocs.body.documents[0];

  if (firstDoc) {
    console.log(`   Selected target doc: "${firstDoc.title}" (ID: ${firstDoc.id})`);

    // 10. Viewer tries to access firstDoc without grant
    const viewerDocAttempt = await request('GET', `/documents/${firstDoc.id}`, null, viewerToken);
    console.log('10. Bypassed Frontend Test: Viewer queries unshared document directly:');
    console.log(`    Response Status: ${viewerDocAttempt.status} (Expected 403)`);
    console.log('    Security Outcome:', viewerDocAttempt.status === 403 ? '🛡️ OBJECT-LEVEL ACL BLOCKED' : '❌ ACL LEAK');

    // 11. Security Guardrail: Administrator attempts to download private document without delegation
    const adminDocAttempt = await request('GET', `/documents/${firstDoc.id}/download`, null, adminToken);
    console.log('11. Zero-Trust Test: Administrator attempts download of private document:');
    console.log(`    Response Status: ${adminDocAttempt.status} (Expected 403 - No Admin Blanket Bypass)`);
    console.log('    Security Outcome:', adminDocAttempt.status === 403 ? '🛡️ NO ADMIN BLANKET BYPASS ENFORCED' : '❌ ADMIN CONTENT LEAK');

    // 12. Owner grants read permission to Viewer
    const grantRes = await request('POST', `/documents/${firstDoc.id}/permissions`, {
      user_email: viewerUser.email,
      permission_level: 'read'
    }, ownerToken);
    console.log('12. Owner delegates read access to Viewer:');
    console.log(`    Status: ${grantRes.status}, Message: "${grantRes.body.message}"`);

    // 13. Viewer now accesses the document
    const viewerAllowedDoc = await request('GET', `/documents/${firstDoc.id}`, null, viewerToken);
    console.log('13. Viewer queries delegated document:');
    console.log(`    Status: ${viewerAllowedDoc.status}, Access Level: ${viewerAllowedDoc.body?.document?.user_access_level}`);
    console.log('    Delegation Outcome:', viewerAllowedDoc.status === 200 ? '✅ ACCESS GRANTED AS EXPECTED' : '❌ DELEGATION FAILED');

    // 14. Owner revokes access from Viewer
    const revokeRes = await request('DELETE', `/documents/${firstDoc.id}/permissions/${viewerUser.id}`, null, ownerToken);
    console.log('14. Owner revokes access from Viewer:');
    console.log(`    Status: ${revokeRes.status}, Message: "${revokeRes.body.message}"`);

    // 15. Viewer tries again after revocation
    const viewerRevokedDoc = await request('GET', `/documents/${firstDoc.id}`, null, viewerToken);
    console.log('15. Viewer queries document after revocation:');
    console.log(`    Response Status: ${viewerRevokedDoc.status} (Expected 403)`);
    console.log('    Revocation Outcome:', viewerRevokedDoc.status === 403 ? '🛡️ IMMEDIATELY REVOKED & BLOCKED' : '❌ REVOCATION FAILED');
  }

  // 16. Tamper Simulation Test
  console.log('\n16. Testing Cryptographic Fraud & Tamper Detection:');
  const tamperRes = await request('POST', '/admin/audit-logs/simulate-tampering', { logId: 1 }, adminToken);
  console.log(`    Tamper Action: ${tamperRes.body.message}`);

  const verifyAfterTamper = await request('GET', '/admin/audit-logs/verify', null, adminToken);
  console.log(`    Verification After Tampering: isValid = ${verifyAfterTamper.body.isValid}, compromisedAtId = ${verifyAfterTamper.body.compromisedAtId}`);
  console.log('    Tamper Detection:', !verifyAfterTamper.body.isValid ? '✅ FRAUD MATHEMATICALLY CAUGHT BY HMAC SIGNATURE' : '❌ TAMPER NOT DETECTED');

  console.log('\n================================================================');
  console.log('🎉 ALL LIVE BACKEND & FRONTEND PERIMETER CHECKS COMPLETE');
  console.log('================================================================\n');
}

runLiveVerification().catch(err => {
  console.error('Verification failed with error:', err);
  process.exit(1);
});
