import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import pool from './config/database.js';

// Service URLs for Railway deployment
const AUTH_SERVICE_URL = 'https://servercode-authservice-production.up.railway.app';
const BRANCH_SERVICE_URL = 'https://servercode-branchservice-production.up.railway.app';
const USER_SERVICE_URL = 'https://servercode-userservice-production.up.railway.app';

const router = express.Router();

// Debug endpoint to check environment
router.get('/debug', (req, res) => {
  res.json({
    env: {
      DB_HOST: process.env.DB_HOST,
      DB_PORT: process.env.DB_PORT,
      DB_NAME: process.env.DB_NAME,
      DB_USER: process.env.DB_USER,
      DB_PASSWORD: process.env.DB_PASSWORD ? '***SET***' : 'NOT SET',
      JWT_SECRET: process.env.JWT_SECRET ? '***SET***' : 'NOT SET',
      PORT: process.env.PORT
    },
    timestamp: new Date().toISOString()
  });
});

// Database test endpoint
router.get('/test-db', async (req, res) => {
  try {
    console.log('Testing database connection...');
    const result = await pool.query('SELECT NOW()');
    console.log('✅ Database connected successfully!');
    res.json({
      status: 'success',
      timestamp: result.rows[0].now,
      message: 'Database connection working'
    });
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    res.status(500).json({
      status: 'error',
      message: 'Database connection failed',
      error: error.message
    });
  }
});

// JWT verification middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    console.log('Decoded user from token:', user);
    req.user = user;
    next();
  });
};

// Health check
router.get('/health', (req, res) => {
  res.json({ status: 'Gateway is running', timestamp: new Date().toISOString() });
});

// Auth routes - proxy to Auth Service
router.post('/auth/login', async (req, res) => {
  try {
    console.log('Gateway: Login request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/api/auth/login`, req.body);
    console.log('Gateway: Login response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Login proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

router.get('/auth/verify', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Verify request for user:', req.user);
    const response = await axios.get(`${AUTH_SERVICE_URL}/api/auth/verify`, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Verify response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Verify proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Create admin user (for branch creators)
router.post('/auth/create-admin', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Create admin request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/api/auth/create-admin`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Create admin response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Create admin proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Create student user
router.post('/auth/create-student', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Create student request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/api/auth/create-student`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Create student response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Create student proxy error:', error.response?.data || error.message);
    res.status(error.response?.data || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});
// Create teacher user
router.post('/auth/create-teacher', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Create teacher request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/api/auth/create-teacher`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Create teacher response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Create teacher proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Protected routes - require authentication
router.use('/api', authenticateToken);

router.get('/api/profile', async (req, res) => {
  try {
    console.log('Gateway: Profile request for user:', req.user);
    // Use auth service to get fresh user data
    const response = await axios.get(`${AUTH_SERVICE_URL}/api/auth/verify`, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Profile response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Profile error:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

// Branch Service proxy routes
router.use('/api/branches', (req, res) => {
  console.log('Gateway: Proxying branch request:', req.method, req.originalUrl);

  // Filter and forward only necessary headers
  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    // url: `${BRANCH_SERVICE_URL}/api${req.originalUrl.replace('/api/branches', '/branches')}`,
    // url: `${BRANCH_SERVICE_URL}${req.originalUrl.replace('/api/branches', '/branches')}`,
    url: `${BRANCH_SERVICE_URL}${req.originalUrl}`, 
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000, // Increased timeout for DB operations
    validateStatus: () => true // Don't throw on any status code
  };

  console.log('Gateway: Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Branch service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Branch Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Branch service error', details: error.message }
      );
    });
});

// Superadmin Branch Service proxy routes (for v1 API)
router.use('/api/v1/superadmin/branches', (req, res) => {
  console.log('Gateway: Proxying superadmin branch request:', req.method, req.originalUrl);

  // Filter and forward only necessary headers
  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${BRANCH_SERVICE_URL}/api${req.originalUrl.replace('/api/v1/superadmin/branches', '/branches')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Superadmin Branch Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Superadmin Branch service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Superadmin Branch Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Superadmin branch service error', details: error.message }
      );
    });
});

// User Service proxy routes
router.use('/api/users', (req, res) => {
  console.log('Gateway: Proxying user request:', req.method, req.originalUrl);

  // Filter and forward only necessary headers
  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}${req.originalUrl.replace('/api/users', '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'User service error', details: error.message }
      );
    });
});

// User Management Endpoints (Implemented locally in Gateway)
router.get('/api/users/superadmins', async (req, res) => {
  try {
    console.log('Gateway: Fetching superadmins');
    
    const query = `
      SELECT id, userid, name, email, role, created_at
      FROM users
      WHERE role = 'superadmin'
      ORDER BY created_at DESC
    `;
    
    const result = await pool.query(query);
    
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Error fetching superadmins:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch superadmins',
      details: error.message
    });
  }
});

router.post('/api/users/generate-userid', async (req, res) => {
  try {
    console.log('Gateway: Generating user ID:', req.body);
    
    const { roleType } = req.body;
    
    if (!roleType) {
      return res.status(400).json({
        success: false,
        error: 'Role type is required'
      });
    }
    
    // Generate user ID based on role
    let prefix;
    switch (roleType) {
      case 'super_administrator':
        prefix = 'SUP';
        break;
      case 'branch_level_manager':
        prefix = 'BLM';
        break;
      case 'access_level_manager':
        prefix = 'ALM';
        break;
      default:
        prefix = 'USR';
    }
    
    // Get next number for this role
    const nextNumberResult = await pool.query(
      `SELECT COALESCE(MAX(CAST(SUBSTRING(userid FROM '[0-9]+$') AS INTEGER)), 0) + 1 as next_num
       FROM users
       WHERE userid LIKE $1`,
      [`${prefix}%`]
    );
    
    const nextNumber = nextNumberResult.rows[0].next_num;
    const userId = `${prefix}${nextNumber.toString().padStart(3, '0')}`;
    
    res.json({
      success: true,
      userId: userId
    });
  } catch (error) {
    console.error('Error generating user ID:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate user ID',
      details: error.message
    });
  }
});

router.post('/api/users/register', async (req, res) => {
  try {
    console.log('Gateway: Registering user:', req.body);
    
    const { userid, password, name, phone, whatsappNumber, gmail, role, selectedSuperAdmin } = req.body;
    
    // Validate required fields
    if (!userid || !password || !name || !phone || !whatsappNumber || !gmail || !role) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }
    
    // Check if userid already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE userid = $1', [userid]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User ID already exists'
      });
    }
    
    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      const userId = require('uuid').v4();
      const hashedPassword = await require('bcryptjs').hash(password, 10);
      const email = `${userid.toLowerCase()}@eims.local`;
      
      // Insert user
      await client.query(`
        INSERT INTO users (id, userid, email, role, name, phone, address, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      `, [userId, userid, email, role, name, phone, gmail]);
      
      // Insert password
      await client.query(`
        INSERT INTO user_auth (user_id, password_hash, created_at)
        VALUES ($1, $2, NOW())
      `, [userId, hashedPassword]);
      
      // If super administrator role, handle super admin relationship
      if (role === 'superadmin' && selectedSuperAdmin) {
        // Insert into superadmin table if it exists
        try {
          await client.query(`
            INSERT INTO superadmin (id, user_id, created_at)
            VALUES ($1, $2, NOW())
          `, [userId, userId]);
        } catch (superadminError) {
          console.log('Superadmin table may not exist, continuing...');
        }
      }
      
      await client.query('COMMIT');
      
      console.log(`✅ User registered successfully: ${userid}`);
      
      res.json({
        success: true,
        message: 'User registered successfully',
        userId: userId,
        email: email
      });
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register user',
      details: error.message
    });
  }
});

// User registrations endpoints
router.get('/api/v1/superadmin/user-registrations', async (req, res) => {
  try {
    console.log('Gateway: Fetching user registrations');
    
    // This would typically return pending registrations
    // For now, return empty array as placeholder
    res.json({
      success: true,
      data: []
    });
  } catch (error) {
    console.error('Error fetching user registrations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user registrations',
      details: error.message
    });
  }
});

router.post('/api/v1/superadmin/user-registrations/:id/approve', async (req, res) => {
  try {
    console.log('Gateway: Approving user registration:', req.params.id);
    
    // This would handle approval of pending registrations
    res.json({
      success: true,
      message: 'User registration approved successfully'
    });
  } catch (error) {
    console.error('Error approving user registration:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to approve user registration',
      details: error.message
    });
  }
});

// Admin API routes for teacher registration reference data
router.use('/api/admin', (req, res) => {
  console.log('Gateway: Proxying admin request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // For deduction templates, we can implement a simple proxy to AuthService or create a dedicated endpoint
  if (req.originalUrl.includes('/deduction-templates')) {
    try {
      // Simple query to get deduction templates from database
      const query = `
        SELECT id, template_name, description, employee_type, is_active
        FROM admin.deduction_templates
        WHERE employee_type = 'teacher' AND is_active = true
        ORDER BY template_name
      `;
      
      pool.query(query, (error, result) => {
        if (error) {
          console.error('Error fetching deduction templates:', error);
          return res.status(500).json({
            success: false,
            error: 'Failed to fetch deduction templates',
            details: error.message
          });
        }
        
        res.json({
          success: true,
          data: result.rows
        });
      });
    } catch (error) {
      console.error('Deduction templates proxy error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: error.message
      });
    }
  } else {
    res.status(404).json({
      success: false,
      error: 'Endpoint not found'
    });
  }
});

// Add more API routes here as needed:
// - /api/students
// - /api/classes
// - /api/attendance
// etc.

export default router;
