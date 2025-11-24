import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import pool from './config/database.js';

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
    const response = await axios.post('http://localhost:8001/api/auth/login', req.body);
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
    const response = await axios.get('http://localhost:8001/api/auth/verify', {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Verify response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Verify proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Protected routes - require authentication
router.use('/api', authenticateToken);

// Example: Get user profile
router.get('/api/profile', async (req, res) => {
  try {
    console.log('Gateway: Profile request for userId:', req.user.userId);
    const userQuery = 'SELECT id, userid, name, email, role FROM users WHERE id = $1';
    const result = await pool.query(userQuery, [req.user.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('Gateway: Profile found:', result.rows[0]);
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Gateway: Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
    url: `http://localhost:8002${req.originalUrl}`,
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

// Add more API routes here as needed:
// - /api/users
// - /api/students
// - /api/classes
// - /api/attendance
// etc.

export default router;
