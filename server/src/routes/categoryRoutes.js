const express = require('express');
const router = express.Router();
const categoryController = require('../controllers/categoryController');
const { authenticateToken } = require('../middleware/auth');
const { requireSystemRole } = require('../middleware/roles');

router.use(authenticateToken);

// All authenticated users can list categories for document tagging
router.get('/', categoryController.getCategories);

// Only administrators can create new enterprise categories
router.post('/', requireSystemRole(['administrator']), categoryController.createCategory);

module.exports = router;
