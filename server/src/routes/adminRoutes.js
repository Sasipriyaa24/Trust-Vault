const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authenticateToken } = require('../middleware/auth');
const { requireSystemRole } = require('../middleware/roles');

// Strict Administrator Authorization Guard
router.use(authenticateToken);
router.use(requireSystemRole(['administrator']));

// Audit trail inspection
router.get('/audit-logs', adminController.getAuditLogs);

// Cryptographic hash chain verification
router.get('/audit-logs/verify', adminController.verifyAuditIntegrity);

// Security test hook: Demonstrate tamper detection & restore
router.post('/audit-logs/simulate-tampering', adminController.simulateTampering);
router.post('/audit-logs/restore-tampering', adminController.restoreTampering);

// User administration
router.get('/users', adminController.getUsers);
router.patch('/users/:id/status', adminController.updateUserStatus);

module.exports = router;
