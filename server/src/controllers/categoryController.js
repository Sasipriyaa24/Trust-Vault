const db = require('../db/db');

/**
 * List all document categories
 */
async function getCategories(req, res) {
  try {
    const categories = await db.getAllCategories();
    res.json({
      total: categories.length,
      categories
    });
  } catch (err) {
    console.error('Get categories error:', err);
    res.status(500).json({ error: 'Failed to retrieve categories.' });
  }
}

/**
 * Create a new document category (Admin only)
 */
async function createCategory(req, res) {
  const { name, description } = req.body;

  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Category name is required.' });
  }

  try {
    const category = await db.createCategory({ name, description });

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CATEGORY_CREATED',
      status: 'SUCCESS',
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: { categoryName: category.name }
    });

    res.status(201).json({
      message: 'Category created successfully.',
      category
    });
  } catch (err) {
    console.error('Create category error:', err);
    res.status(400).json({ error: err.message });
  }
}

module.exports = {
  getCategories,
  createCategory
};
