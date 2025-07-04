const express = require('express');
const router = express.Router();
const adminController = require('../controllers/admin.controller');
const { protect, authorize } = require('../middleware/auth.middleware');

// Public routes
router.post('/register', adminController.register);
router.post('/login', adminController.login);

module.exports = router; 