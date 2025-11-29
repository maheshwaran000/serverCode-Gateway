import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import pool from './config/database.js';

// Environment-based service URLs
const isDevelopment = process.env.NODE_ENV !== 'production';

// Development URLs (local services)
const AUTH_SERVICE_URL = isDevelopment
  ? 'http://localhost:8001/api/auth'
  : 'https://servercode-authservice-production.up.railway.app/api/auth';

const BRANCH_SERVICE_URL = isDevelopment
  ? 'http://localhost:8002/api/branches'
  : 'https://servercode-branchservice-production.up.railway.app/api/branches';

const USER_SERVICE_URL = isDevelopment
  ? 'http://localhost:8003/api/users'
  : 'https://servercode-userservice-production.up.railway.app/api/users';

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
    const response = await axios.post(`${AUTH_SERVICE_URL}/login`, req.body);
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
    const response = await axios.get(`${AUTH_SERVICE_URL}/verify`, {
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
    const response = await axios.post(`${AUTH_SERVICE_URL}/create-admin`, req.body, {
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
    const response = await axios.post(`${AUTH_SERVICE_URL}/create-student`, req.body, {
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
    const response = await axios.post(`${AUTH_SERVICE_URL}/create-teacher`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Create teacher response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Create teacher proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Create staff user
router.post('/auth/create-staff', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Create staff request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/create-staff`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Create staff response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Create staff proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Protected routes - require authentication
router.use('/api', authenticateToken);

router.get('/api/profile', async (req, res) => {
  try {
    console.log('Gateway: Profile request for user:', req.user);
    // Use auth service to get fresh user data
    const response = await axios.get(`${AUTH_SERVICE_URL}/verify`, {
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

  // Extract the path after /api/branches and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/branches', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${BRANCH_SERVICE_URL}${pathAfterApi}`,
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

  // Extract the path after /api/v1/superadmin/branches and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/v1/superadmin/branches', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${BRANCH_SERVICE_URL}${pathAfterApi}`,
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

  // Extract the path after /api/users and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/users', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}${pathAfterApi}`,
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

// Classes Service proxy routes
router.use('/api/classes', (req, res) => {
  console.log('Gateway: Proxying Classes request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  const CLASSES_SERVICE_URL = isDevelopment
    ? 'http://localhost:8004'
    : 'https://servercode-classesservice-production.up.railway.app';

  // Extract the path after /api/classes and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/classes', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teachers/available
router.use('/api/teachers/available', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/available request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  const CLASSES_SERVICE_URL = isDevelopment
    ? 'http://localhost:8004'
    : 'https://servercode-classesservice-production.up.railway.app';

  // Extract the path after /api/teachers/available and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/available', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/available${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/available Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/available response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/available proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teachers/all
router.use('/api/teachers/all', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/all request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  const CLASSES_SERVICE_URL = isDevelopment
    ? 'http://localhost:8004'
    : 'https://servercode-classesservice-production.up.railway.app';

  // Extract the path after /api/teachers/all and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/all', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/all${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/all Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/all response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/all proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for academic-years
router.use('/api/academic-years', (req, res) => {
  console.log('Gateway: Proxying Classes academic-years request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  const CLASSES_SERVICE_URL = isDevelopment
    ? 'http://localhost:8004'
    : 'https://servercode-classesservice-production.up.railway.app';

  // Extract the path after /api/academic-years and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/academic-years', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/academic-years${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service academic-years Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service academic-years response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service academic-years proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// HRMS Service proxy routes
router.use('/api/hrms', (req, res) => {
  console.log('Gateway: Proxying HRMS request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const HRMS_SERVICE_URL = isDevelopment
    ? 'http://localhost:8005/api'
    : 'https://servercode-hrmsservice-production.up.railway.app/api';

  // Extract the path after /api/hrms and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/hrms', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${HRMS_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: HRMS Service Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: HRMS service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: HRMS Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'HRMS service error', details: error.message }
      );
    });
});

// AdminService proxy routes for other admin endpoints (not academic-years)
router.use('/api/admin-service', (req, res) => {
  console.log('Gateway: Proxying AdminService request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const ADMIN_SERVICE_URL = isDevelopment
    ? 'http://localhost:8006/api'
    : 'https://servercode-adminservice-production.up.railway.app/api';

  // Extract the path after /api/admin-service and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/admin-service', '');
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for bus routes
router.use('/api/bus-routes', (req, res) => {
  console.log('Gateway: Proxying AdminService bus-routes request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const ADMIN_SERVICE_URL = isDevelopment
    ? 'http://localhost:8006/api/bus-routes'
    : 'https://servercode-adminservice-production.up.railway.app/api/bus-routes';

  // Extract the path after /api/bus-routes and append to base URL
  let pathAfterApi = req.originalUrl.replace('/api/bus-routes', '');

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService bus-routes Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService bus-routes response status:', response.status);
      console.log('Gateway: Bus routes response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService bus-routes proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for hostels
router.use('/api/hostels', (req, res) => {
  console.log('Gateway: Proxying AdminService hostels request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const ADMIN_SERVICE_URL = isDevelopment
    ? 'http://localhost:8006/api/hostels'
    : 'https://servercode-adminservice-production.up.railway.app/api/hostels';

  // Extract the path after /api/hostels and append to base URL
  let pathAfterApi = req.originalUrl.replace('/api/hostels', '');

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService hostels Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService hostels response status:', response.status);
      console.log('Gateway: Hostels response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService hostels proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for academic exams
router.use('/api/academic-exams', (req, res) => {
  console.log('Gateway: Proxying AdminService academic-exams request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const ADMIN_SERVICE_URL = isDevelopment
    ? 'http://localhost:8006/api/academic-exams'
    : 'https://servercode-adminservice-production.up.railway.app/api/academic-exams';

  // Extract the path after /api/academic-exams and append to base URL
  let pathAfterApi = req.originalUrl.replace('/api/academic-exams', '');

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService academic-exams Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService academic-exams response status:', response.status);
      console.log('Gateway: Academic exams response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService academic-exams proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for fee templates
router.use('/api/fee-templates', (req, res) => {
  console.log('Gateway: Proxying AdminService fee-templates request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const ADMIN_SERVICE_URL = isDevelopment
    ? 'http://localhost:8006/api/fee-templates'
    : 'https://servercode-adminservice-production.up.railway.app/api/fee-templates';

  // Extract the path after /api/fee-templates and append to base URL
  let pathAfterApi = req.originalUrl.replace('/api/fee-templates', '');

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService fee-templates Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService fee-templates response status:', response.status);
      console.log('Gateway: Fee templates response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService fee-templates proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// Staff Management Endpoints
router.get('/api/staff', async (req, res) => {
  try {
    console.log('Gateway: Fetching all staff');
    
    // Simplified query first to test connection
    const query = `
      SELECT
        s.staff_id,
        s.department,
        s.designation,
        s.employment_type,
        s.qualification,
        s.specialization,
        s.experience_years,
        s.status,
        s.created_at,
        u.name,
        u.email,
        b.branch_name
      FROM branch.staff s
      LEFT JOIN users u ON s.user_id = u.id
      LEFT JOIN superadmin.branches b ON s.branch_id = b.id
      ORDER BY s.created_at DESC
    `;
    
    const result = await pool.query(query);
    
    res.json({
      success: true,
      data: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching staff:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch staff',
      details: error.message
    });
  }
});

router.get('/api/staff/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('Gateway: Fetching staff by user ID:', userId);
    
    const query = `
      SELECT
        s.staff_id,
        s.department,
        s.designation,
        s.employment_type,
        s.subjects,
        s.qualification,
        s.specialization,
        s.experience_years,
        s.basic_salary,
        s.hra,
        s.conveyance,
        s.medical,
        s.lta,
        s.other_allowances,
        s.ctc,
        s.joining_date,
        s.status,
        s.emergency_contact,
        s.emergency_phone,
        s.bank_name,
        s.account_number,
        s.ifsc_code,
        s.account_holder_name,
        s.bank_branch,
        s.account_type,
        s.photo_url,
        s.id_proof_url,
        s.resume_url,
        s.qualification_certificates,
        s.experience_certificates,
        s.previous_experience,
        s.created_at,
        s.updated_at,
        u.name,
        u.email,
        u.phone,
        u.address,
        b.branch_name
      FROM branch.staff s
      LEFT JOIN users u ON s.user_id = u.id
      LEFT JOIN superadmin.branches b ON s.branch_id = b.id
      WHERE s.user_id = $1
    `;
    
    const result = await pool.query(query, [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Staff not found'
      });
    }
    
    const staff = result.rows[0];
    
    res.json({
      success: true,
      data: {
        ...staff,
        subjects: staff.subjects || [],
        qualification_certificates: staff.qualification_certificates || [],
        experience_certificates: staff.experience_certificates || [],
        previous_experience: staff.previous_experience || [],
        has_photo: !!staff.photo_url,
        has_id_proof: !!staff.id_proof_url,
        has_resume: !!staff.resume_url
      }
    });
  } catch (error) {
    console.error('Error fetching staff by user ID:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch staff',
      details: error.message
    });
  }
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

// Teacher Management Endpoints
router.get('/api/teachers', async (req, res) => {
  try {
    console.log('Gateway: Fetching all teachers');
    
    // Simplified query first to test connection
    const query = `
      SELECT
        t.teacher_id,
        t.department,
        t.qualification,
        t.specialization,
        t.status,
        t.created_at,
        u.name,
        u.email,
        b.branch_name
      FROM branch.teachers t
      LEFT JOIN users u ON t.user_id = u.id
      LEFT JOIN superadmin.branches b ON t.branch_id = b.id
      ORDER BY t.created_at DESC
    `;
    
    const result = await pool.query(query);
    
    res.json({
      success: true,
      data: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching teachers:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch teachers',
      details: error.message
    });
  }
});

router.get('/api/teachers/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('Gateway: Fetching teacher by user ID:', userId);
    
    const query = `
      SELECT
        t.teacher_id,
        t.department,
        t.subjects,
        t.qualification,
        t.specialization,
        t.experience_years,
        t.basic_salary,
        t.hra,
        t.conveyance,
        t.medical,
        t.lta,
        t.other_allowances,
        t.ctc,
        t.joining_date,
        t.status,
        t.bank_name,
        t.account_number,
        t.ifsc_code,
        t.account_holder_name,
        t.bank_branch,
        t.account_type,
        t.photo_url,
        t.id_proof_url,
        t.resume_url,
        t.qualification_certificates,
        t.experience_certificates,
        t.created_at,
        t.updated_at,
        u.name,
        u.email,
        u.phone,
        u.address,
        b.branch_name
      FROM branch.teachers t
      LEFT JOIN users u ON t.user_id = u.id
      LEFT JOIN superadmin.branches b ON t.branch_id = b.id
      WHERE t.user_id = $1
    `;
    
    const result = await pool.query(query, [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Teacher not found'
      });
    }
    
    const teacher = result.rows[0];
    
    res.json({
      success: true,
      data: {
        ...teacher,
        subjects: teacher.subjects || [],
        qualification_certificates: teacher.qualification_certificates || [],
        experience_certificates: teacher.experience_certificates || [],
        has_photo: !!teacher.photo_url,
        has_id_proof: !!teacher.id_proof_url,
        has_resume: !!teacher.resume_url
      }
    });
  } catch (error) {
    console.error('Error fetching teacher by user ID:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch teacher',
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
