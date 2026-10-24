const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/demo-switch', authController.demoSwitchUser);

// Protected routes
router.get('/me', authenticateToken, authController.me);

module.exports = router;
