const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const pool = require('./config/database.js');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');


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

const CLASSES_SERVICE_URL = isDevelopment
  ? 'http://localhost:8004'
  : 'https://servercodeclassesservice-production.up.railway.app';

const HRMS_SERVICE_URL = isDevelopment
  ? 'http://localhost:8005/api'
  : 'https://servercode-hrmsservice-production.up.railway.app/api';

const ADMIN_SERVICE_URL = isDevelopment
  ? 'http://localhost:8006'
  : 'https://servercode-adminservice-production.up.railway.app';

const FEE_MANAGEMENT_SERVICE_URL = isDevelopment
  ? 'http://localhost:8007'
  : 'https://servercode-feemanagement-production.up.railway.app';

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

    const response = await axios.post(
      `${AUTH_SERVICE_URL}/create-student`,
      req.body,
      { headers: { Authorization: req.headers.authorization } }
    );

    console.log('Gateway: Create student response:', response.data);
    return res.json(response.data);

  } catch (error) {
    console.error(
      'Gateway: Create student proxy error:',
      error.response?.data || error.message
    );

    const status = error.response?.status || 500;
    const errData = error.response?.data || {
      success: false,
      error: 'Auth service error'
    };

    return res.status(status).json(errData);
  }
});

// Create teacher user
router.post('/api/auth/create-teacher', authenticateToken, async (req, res) => {
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
router.post('/api/auth/create-staff', authenticateToken, async (req, res) => {
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

// Direct branch status toggle endpoint (Active ↔ Inactive)
router.post('/api/branches/:id/toggle-status', async (req, res) => {
  try {
    console.log('Gateway: Direct branch status toggle request:', req.params.id);
    
    // Check user permissions
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err || (user.role !== 'superadmin' && user.role !== 'access_manager')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: Only superadmin or access_manager can toggle branch status'
        });
      }
      
      try {
        // Get current branch status
        const currentStatusResult = await pool.query(
          `SELECT status, branch_name, branch_code FROM superadmin.branches WHERE id = $1`,
          [req.params.id]
        );
        
        if (currentStatusResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            error: 'Branch not found'
          });
        }
        
        const currentStatus = currentStatusResult.rows[0].status;
        let newStatus;
        
        // Toggle logic: Active ↔ Inactive
        if (currentStatus === 'Active') {
          newStatus = 'Inactive';
        } else if (currentStatus === 'Inactive') {
          newStatus = 'Active';
        } else {
          // For other statuses (Pending, Rejected), set to Active by default
          newStatus = 'Active';
        }
        
        // Update branch status
        const updateResult = await pool.query(
          `UPDATE superadmin.branches
           SET status = $1, updated_at = NOW()
           WHERE id = $2
           RETURNING *`,
          [newStatus, req.params.id]
        );
        
        const actionDescription = currentStatus === 'Active' ? 'deactivated' : 'activated';
        
        // Log audit event
        try {
          await pool.query(`
            INSERT INTO audit_logs (user_id, action, details, status, created_at)
            VALUES ($1, $2, $3, $4, NOW())
          `, [
            user.userId,
            'toggle_branch_status',
            `${actionDescription} branch: ${currentStatusResult.rows[0].branch_name} (${currentStatusResult.rows[0].branch_code}) - ${currentStatus} → ${newStatus}`,
            'success'
          ]);
          console.log('✅ Branch status toggle logged successfully');
        } catch (auditError) {
          console.log('⚠️ Audit logging skipped for branch status toggle');
        }
        
        console.log(`✅ Branch ${req.params.id} ${actionDescription} by user ${user.userId} (${currentStatus} → ${newStatus})`);
        
        res.json({
          success: true,
          message: `Branch ${actionDescription} successfully`,
          data: {
            ...updateResult.rows[0],
            status_change: {
              from: currentStatus,
              to: newStatus,
              action: actionDescription
            }
          }
        });
        
      } catch (dbError) {
        console.error('Database error in branch status toggle:', dbError);
        res.status(500).json({
          success: false,
          error: 'Failed to toggle branch status',
          details: dbError.message
        });
      }
    });
    
  } catch (error) {
    console.error('Branch status toggle error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to toggle branch status',
      details: error.message
    });
  }
});

// Direct branch status update endpoint with explicit status
router.post('/api/branches/:id/update-status', async (req, res) => {
  try {
    console.log('Gateway: Direct branch status update request:', req.params.id, 'New status:', req.body.status);
    
    // Check user permissions
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err || (user.role !== 'superadmin' && user.role !== 'access_manager')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: Only superadmin or access_manager can update branch status'
        });
      }
      
      try {
        const { status } = req.body;
        
        // Validate status
        const validStatuses = ['Active', 'Inactive', 'Pending', 'Rejected'];
        if (!validStatuses.includes(status)) {
          return res.status(400).json({
            success: false,
            error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
          });
        }
        
        // Get current branch info
        const currentInfoResult = await pool.query(
          `SELECT status, branch_name, branch_code FROM superadmin.branches WHERE id = $1`,
          [req.params.id]
        );
        
        if (currentInfoResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            error: 'Branch not found'
          });
        }
        
        const currentStatus = currentInfoResult.rows[0].status;
        
        // Update branch status
        const updateResult = await pool.query(
          `UPDATE superadmin.branches
           SET status = $1, updated_at = NOW()
           WHERE id = $2
           RETURNING *`,
          [status, req.params.id]
        );
        
        // Log audit event
        try {
          await pool.query(`
            INSERT INTO audit_logs (user_id, action, details, status, created_at)
            VALUES ($1, $2, $3, $4, NOW())
          `, [
            user.userId,
            'update_branch_status',
            `Updated branch status: ${currentInfoResult.rows[0].branch_name} (${currentInfoResult.rows[0].branch_code}) - ${currentStatus} → ${status}`,
            'success'
          ]);
          console.log('✅ Branch status update logged successfully');
        } catch (auditError) {
          console.log('⚠️ Audit logging skipped for branch status update');
        }
        
        console.log(`✅ Branch ${req.params.id} status updated by user ${user.userId} (${currentStatus} → ${status})`);
        
        res.json({
          success: true,
          message: 'Branch status updated successfully',
          data: {
            ...updateResult.rows[0],
            status_change: {
              from: currentStatus,
              to: status,
              action: 'updated'
            }
          }
        });
        
      } catch (dbError) {
        console.error('Database error in branch status update:', dbError);
        res.status(500).json({
          success: false,
          error: 'Failed to update branch status',
          details: dbError.message
        });
      }
    });
    
  } catch (error) {
    console.error('Branch status update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update branch status',
      details: error.message
    });
  }
});

// Direct approve/reject endpoints for branches (bypass BranchService for clarity)
router.post('/api/branches/:id/approve', async (req, res) => {
  try {
    console.log('Gateway: Direct branch approve request:', req.params.id);
    
    // Check user permissions
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err || (user.role !== 'superadmin' && user.role !== 'access_manager')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: Only superadmin or access_manager can approve branches'
        });
      }
      
      try {
        // Update branch status to Active
        const updateResult = await pool.query(
          `UPDATE superadmin.branches
           SET status = 'Active', updated_at = NOW()
           WHERE id = $1
           RETURNING *`,
          [req.params.id]
        );
        
        if (updateResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            error: 'Branch not found'
          });
        }
        
        // Log audit event
        try {
          await pool.query(`
            INSERT INTO audit_logs (user_id, action, details, status, created_at)
            VALUES ($1, $2, $3, $4, NOW())
          `, [
            user.userId,
            'approve_branch',
            `Approved branch: ${updateResult.rows[0].branch_name} (${updateResult.rows[0].branch_code})`,
            'success'
          ]);
          console.log('✅ Branch approval logged successfully');
        } catch (auditError) {
          console.log('⚠️ Audit logging skipped for branch approval');
        }
        
        console.log(`✅ Branch ${req.params.id} approved by user ${user.userId}`);
        
        res.json({
          success: true,
          message: 'Branch approved successfully',
          data: updateResult.rows[0]
        });
        
      } catch (dbError) {
        console.error('Database error in branch approval:', dbError);
        res.status(500).json({
          success: false,
          error: 'Failed to approve branch',
          details: dbError.message
        });
      }
    });
    
  } catch (error) {
    console.error('Branch approval error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to approve branch',
      details: error.message
    });
  }
});

router.post('/api/branches/:id/reject', async (req, res) => {
  try {
    console.log('Gateway: Direct branch reject request:', req.params.id);
    
    // Check user permissions
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err || (user.role !== 'superadmin' && user.role !== 'access_manager')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied: Only superadmin or access_manager can reject branches'
        });
      }
      
      try {
        // Update branch status to Rejected
        const updateResult = await pool.query(
          `UPDATE superadmin.branches
           SET status = 'Rejected', updated_at = NOW()
           WHERE id = $1
           RETURNING *`,
          [req.params.id]
        );
        
        if (updateResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            error: 'Branch not found'
          });
        }
        
        // Log audit event
        try {
          await pool.query(`
            INSERT INTO audit_logs (user_id, action, details, status, created_at)
            VALUES ($1, $2, $3, $4, NOW())
          `, [
            user.userId,
            'reject_branch',
            `Rejected branch: ${updateResult.rows[0].branch_name} (${updateResult.rows[0].branch_code})`,
            'success'
          ]);
          console.log('✅ Branch rejection logged successfully');
        } catch (auditError) {
          console.log('⚠️ Audit logging skipped for branch rejection');
        }
        
        console.log(`✅ Branch ${req.params.id} rejected by user ${user.userId}`);
        
        res.json({
          success: true,
          message: 'Branch rejected successfully',
          data: updateResult.rows[0]
        });
        
      } catch (dbError) {
        console.error('Database error in branch rejection:', dbError);
        res.status(500).json({
          success: false,
          error: 'Failed to reject branch',
          details: dbError.message
        });
      }
    });
    
  } catch (error) {
    console.error('Branch rejection error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reject branch',
      details: error.message
    });
  }
});

// Specific route for academic years - proxy to ClassesService
router.use('/api/branches/academic-years', (req, res) => {
  console.log('Gateway: Proxying academic-years request to ClassesService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/branches/academic-years and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/branches/academic-years', '').trim();

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

// Specific route for transport routes - proxy to AdminService
router.use('/api/branches/transport/routes', (req, res) => {
  console.log('Gateway: Proxying transport routes request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/transport/routes and append to bus-routes
  const pathAfterApi = req.originalUrl.replace('/api/branches/transport/routes', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/bus-routes${pathAfterApi}`,
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

// Specific route for blocks - proxy to AdminService
router.use('/api/branches/blocks', (req, res) => {
  console.log('Gateway: Proxying blocks request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/blocks and append to blocks
  const pathAfterApi = req.originalUrl.replace('/api/branches/blocks', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/blocks${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService blocks Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService blocks response status:', response.status);
      console.log('Gateway: Blocks response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService blocks proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// Specific route for rooms - proxy to AdminService
router.use('/api/branches/rooms', (req, res) => {
  console.log('Gateway: Proxying rooms request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/rooms and append to rooms
  const pathAfterApi = req.originalUrl.replace('/api/branches/rooms', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/rooms${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService rooms Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService rooms response status:', response.status);
      console.log('Gateway: Rooms response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService rooms proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// Specific route for allocate-room - proxy to AdminService
router.use('/api/branches/allocate-room', (req, res) => {
  console.log('Gateway: Proxying allocate-room request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/allocate-room and append to allocate-room
  const pathAfterApi = req.originalUrl.replace('/api/branches/allocate-room', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/allocate-room${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService allocate-room Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService allocate-room response status:', response.status);
      console.log('Gateway: Allocate-room response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService allocate-room proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// Specific route for floors - proxy to AdminService
router.use('/api/branches/floors', (req, res) => {
  console.log('Gateway: Proxying floors request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/floors and append to floors
  const pathAfterApi = req.originalUrl.replace('/api/branches/floors', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/floors${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService floors Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService floors response status:', response.status);
      console.log('Gateway: Floors response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService floors proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// Specific route for hostels - proxy to AdminService
router.use('/api/branches/hostels', (req, res) => {
  console.log('Gateway: Proxying hostels request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches/hostels and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/branches/hostels', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/hostels${pathAfterApi}`,
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

// Branch Service proxy routes with special handling for admin endpoints
router.use('/api/branches', (req, res) => {
  console.log('Gateway: Processing branch request:', req.method, req.originalUrl);

  // Handle admin endpoints directly in Gateway
  if (req.originalUrl.includes('/admins')) {
    console.log('Gateway: Handling admin endpoint directly');
    
    // Extract branch ID from URL
    const branchIdMatch = req.originalUrl.match(/\/api\/branches\/([^/]+)\/admins/);
    if (!branchIdMatch) {
      return res.status(400).json({
        success: false,
        error: 'Invalid branch ID format'
      });
    }

    const branchId = branchIdMatch[1];
    
    try {
      console.log('Gateway: Fetching admin users for branch:', branchId);
      
      const query = `
        SELECT
          u.userid,
          u.email,
          u.name,
          u.phone,
          u.created_at
        FROM users u
        WHERE u.role = 'admin' AND u.branch_id = $1
        ORDER BY u.created_at ASC
      `;
      
      pool.query(query, [branchId], (error, result) => {
        if (error) {
          console.error('Gateway: Error fetching branch admin users:', error);
          return res.status(500).json({
            success: false,
            error: 'Failed to fetch admin users',
            details: error.message
          });
        }
        
        console.log('Gateway: Successfully fetched admin users:', result.rows.length);
        res.json({
          success: true,
          data: result.rows
        });
      });
      
    } catch (error) {
      console.error('Gateway: Error in admin endpoint:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: error.message
      });
    }
    return; // Don't continue to proxy logic
  }

  // Filter and forward only necessary headers for other branch requests
  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/branches and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/branches', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${BRANCH_SERVICE_URL}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000, // Increased timeout for DB operations
    validateStatus: () => true // Don't throw on any status code
  };

  console.log('Gateway: Axios config for branch proxy:', {
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
  const pathAfterApi = req.originalUrl.replace('/api/v1/superadmin/branches', '').trim();
  
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

// User Service proxy routes for branch users endpoint (must come before generic /api/users)
router.use('/api/users/branch/:branchId', (req, res) => {
  console.log('Gateway: Proxying branch users request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}/branch/${req.params.branchId}${req.originalUrl.replace(`/api/users/branch/${req.params.branchId}`, '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service branch users Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service branch users response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service branch users proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'User service error', details: error.message }
      );
    });
  });      
// User Service proxy routes for individual student details
router.use('/api/users/students/:id', (req, res) => {
  console.log('Gateway: Proxying students/:id request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}/students/${req.params.id}${req.originalUrl.replace(`/api/users/students/${req.params.id}`, '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service students/:id Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service students/:id response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service students/:id proxy error:', error.response?.data || error.message);
      res.status(error.response?.status || 500).json(error.response?.data || { error: 'User service error', details: error.message });
    });
});

// User Service proxy routes for individual teacher details
router.use('/api/users/teachers/:id', (req, res) => {
  console.log('Gateway: Proxying teachers/:id request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}/teachers/${req.params.id}${req.originalUrl.replace(`/api/users/teachers/${req.params.id}`, '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service teachers/:id Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service teachers/:id response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service teachers/:id proxy error:', error.response?.data || error.message);
      res.status(error.response?.status || 500).json(error.response?.data || { error: 'User service error', details: error.message });
    });
});

// User Service proxy routes for individual staff details
router.use('/api/users/staff/:id', (req, res) => {
  console.log('Gateway: Proxying staff/:id request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}/staff/${req.params.id}${req.originalUrl.replace(`/api/users/staff/${req.params.id}`, '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service staff/:id Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service staff/:id response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service staff/:id proxy error:', error.response?.data || error.message);
      res.status(error.response?.status || 500).json(error.response?.data || { error: 'User service error', details: error.message });
    });
});

// User Service proxy routes for teacher profile endpoints
router.use('/api/users/teachers/profile', (req, res) => {
  console.log('Gateway: Proxying teachers/profile request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${USER_SERVICE_URL}/teachers/profile${req.originalUrl.replace('/api/users/teachers/profile', '')}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: User Service teachers/profile Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: User service teachers/profile response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: User Service teachers/profile proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'User service error', details: error.message }
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
  const pathAfterApi = req.originalUrl.replace('/api/users', '').trim();

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

// Classes Service proxy routes for specific teacher class
router.use('/api/classes/teachers/:teacherId/class', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/:teacherId/class request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Construct the target URL correctly
  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/teachers/${req.params.teacherId}/class`;
  
  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/:teacherId/class Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/:teacherId/class response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/:teacherId/class proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for specific teacher timetable
router.use('/api/classes/teachers/:teacherId/timetable', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/:teacherId/timetable request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Construct the target URL correctly
  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/teachers/${req.params.teacherId}/timetable`;
  
  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/:teacherId/timetable Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/:teacherId/timetable response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/:teacherId/timetable proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for specific teacher students
// router.use('/api/classes/teachers/:teacherId/students', (req, res) => {
//   console.log('Gateway: Proxying Classes teachers/:teacherId/students request:', req.method, req.originalUrl);

//   const forwardedHeaders = {
//     'authorization': req.headers.authorization,
//     'content-type': req.headers['content-type'],
//     'accept': req.headers.accept,
//     'user-agent': req.headers['user-agent'],
//     'x-user-role': req.headers['x-user-role']
//   };

//   const CLASSES_SERVICE_URL = isDevelopment
//     ? 'http://localhost:8004'
//     : 'https://servercode-classesservice-production.up.railway.app';

//   // Construct the target URL correctly
//   const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/teachers/${req.params.teacherId}/students`;
  
//   const axiosConfig = {
//     method: req.method,
//     url: targetUrl,
//     headers: forwardedHeaders,
//     data: req.method !== 'GET' ? req.body : undefined,
//     timeout: 60000,
//     validateStatus: () => true
//   };

//   console.log('Gateway: Classes Service teachers/:teacherId/students Axios config:', {
//     method: axiosConfig.method,
//     url: axiosConfig.url,
//     hasAuth: !!axiosConfig.headers.authorization,
//     hasData: !!axiosConfig.data
//   });

//   axios(axiosConfig)
//     .then(response => {
//       console.log('Gateway: Classes service teachers/:teacherId/students response status:', response.status);
//       res.status(response.status).json(response.data);
//     })
//     .catch(error => {
//       console.error('Gateway: Classes Service teachers/:teacherId/students proxy error:', {
//         message: error.message,
//         status: error.response?.status,
//         data: error.response?.data
//       });
//       res.status(error.response?.status || 500).json(
//         error.response?.data || { error: 'Classes service error', details: error.message }
//       );
//     });
// });
router.use('/api/classes/teachers/students', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/students request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/teachers/students`;

  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  axios(axiosConfig)
    .then(response => res.status(response.status).json(response.data))
    .catch(error => {
      res.status(error.response?.status || 500)
        .json(error.response?.data || { error: 'Classes service error' });
    });
});


// Classes Service proxy routes for class students
router.use('/api/classes/:id/students', (req, res) => {
  console.log('Gateway: Proxying Classes students request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/classes/:id/students and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/classes/:id/students', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/${req.params.id}/students${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service students Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service students response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service students proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teacher's class
router.use('/api/teachers/my-class', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/my-class request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/my-class and append to base URL
  // Clean the URL by trimming whitespace and newlines
  const pathAfterApi = req.originalUrl.replace('/api/teachers/my-class', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/my-class${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/my-class Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/my-class response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/my-class proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teacher's students
router.use('/api/teachers/my-students', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/my-students request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/my-students and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/my-students', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/my-students${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/my-students Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/my-students response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/my-students proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes - Generic (must come last)
router.use('/api/classes', (req, res) => {
  console.log('Gateway: Proxying Classes request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/classes and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/classes', '').trim();
  
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

  // Extract the path after /api/teachers/available and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/available', '').trim();
  
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

// Classes Service proxy routes for teacher eligibility check
router.use('/api/teachers/eligibility', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/eligibility request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/eligibility and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/eligibility', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/eligibility Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/eligibility response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/eligibility proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teacher notifications
router.use('/api/teachers/notify', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/notify request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/notify and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/notify', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/notify Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/notify response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/notify proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teacher my-notifications
router.use('/api/teachers/my-notifications', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/my-notifications request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/my-notifications and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/my-notifications', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/my-notifications${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/my-notifications Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/my-notifications response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/my-notifications proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for teacher notification status
router.use('/api/teachers/notification-status', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/notification-status request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/notification-status and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/notification-status', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/notification-status${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/notification-status Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/notification-status response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/notification-status proxy error:', {
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

  // Extract the path after /api/teachers/all and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/all', '').trim();
  
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

// Classes Service proxy routes for teachers/my-timetable
router.use('/api/teachers/my-timetable', (req, res) => {
  console.log('Gateway: Proxying Classes teachers/my-timetable request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/teachers/my-timetable and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/teachers/my-timetable', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/teachers/my-timetable${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service teachers/my-timetable Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service teachers/my-timetable response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service teachers/my-timetable proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// Classes Service proxy routes for timetable CRUD operations
router.use('/api/timetable/:id', (req, res) => {
  console.log('Gateway: Proxying Classes timetable/:id request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the timetable ID and construct target URL
  const timetableId = req.params.id;
  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/timetable/${timetableId}`;
  
  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service timetable/:id Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service timetable/:id response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service timetable/:id proxy error:', {
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

  // Extract the path after /api/academic-years and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/academic-years', '').trim();
  
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

// Classes Service proxy routes for attendance endpoints
router.use('/api/classes/:id/attendance', (req, res) => {
  console.log('Gateway: Proxying Classes attendance request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/classes/:id/attendance and append to base URL
  const pathAfterApi = req.originalUrl.replace(`/api/classes/${req.params.id}/attendance`, '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/${req.params.id}/attendance${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service attendance Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service attendance response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service attendance proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});
// Classes Service proxy routes for individual attendance records (MUST come before generic classes route)
// router.use('/api/attendance/:id', (req, res) => {
//   console.log('Gateway: Proxying Classes attendance record request:', req.method, req.originalUrl);

//   const forwardedHeaders = {
//     'authorization': req.headers.authorization,
//     'content-type': req.headers['content-type'],
//     'accept': req.headers.accept,
//     'user-agent': req.headers['user-agent'],
//     'x-user-role': req.headers['x-user-role']
//   };

//   const CLASSES_SERVICE_URL = isDevelopment
//     ? 'http://localhost:8004'
//     : 'https://servercode-classesservice-production.up.railway.app';

//   // Extract the path after /api/attendance/:id and append to base URL
//   const pathAfterApi = req.originalUrl.replace(`/api/attendance/${req.params.id}`, '');
  
//   const axiosConfig = {
//     method: req.method,
//     url: `${CLASSES_SERVICE_URL}/api/classes/attendance/${req.params.id}${pathAfterApi}`,
//     headers: forwardedHeaders,
//     data: req.method !== 'GET' ? req.body : undefined,
//     timeout: 60000,
//     validateStatus: () => true
//   };

//   console.log('Gateway: Classes Service attendance record Axios config:', {
//     method: axiosConfig.method,
//     url: axiosConfig.url,
//     hasAuth: !!axiosConfig.headers.authorization,
//     hasData: !!axiosConfig.data
//   });

//   axios(axiosConfig)
//     .then(response => {
//       console.log('Gateway: Classes service attendance record response status:', response.status);
//       res.status(response.status).json(response.data);
//     })
//     .catch(error => {
//       console.error('Gateway: Classes Service attendance record proxy error:', {
//         message: error.message,
//         status: error.response?.status,
//         data: error.response?.data
//       });
//       res.status(error.response?.status || 500).json(
//         error.response?.data || { error: 'Classes service error', details: error.message }
//       );
//     });
// });
router.use('/api/attendance/:id', (req, res) => {
  console.log('Gateway: Proxying Attendance request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    authorization: req.headers.authorization,
    'content-type': req.headers['content-type'],
    accept: req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role'],
  };

  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/attendance/${req.params.id}`;

  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway → Classes Attendance URL:', targetUrl);

  axios(axiosConfig)
    .then(r => res.status(r.status).json(r.data))
    .catch(error => {
      console.error('Gateway Attendance proxy error:', error.response?.data || error.message);
      res.status(error.response?.status || 500).json(error.response?.data || { error: 'Classes service error' });
    });
});


// Classes Service proxy routes for date-specific attendance
router.use('/api/attendance/date/:date', (req, res) => {
  console.log('Gateway: Proxying Classes attendance by date request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/attendance/date/:date and append to base URL
  const pathAfterApi = req.originalUrl.replace(`/api/attendance/date/${req.params.date}`, '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/attendance/date/${req.params.date}${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service attendance by date Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service attendance by date response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service attendance by date proxy error:', {
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

  // Extract the path after /api/hrms and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/hrms', '').trim();
  
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

  // Extract the path after /api/admin-service and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/admin-service', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api${pathAfterApi}`,
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

  // Extract the path after /api/bus-routes and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/bus-routes', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/bus-routes${pathAfterApi}`,
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

  // Extract the path after /api/hostels and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/hostels', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/hostels${pathAfterApi}`,
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

// AdminService proxy routes for events
router.use('/api/events', (req, res) => {
  console.log('Gateway: Proxying AdminService events request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/events and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/events', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/events${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService events Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService events response status:', response.status);
      console.log('Gateway: Events response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService events proxy error:', {
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

  // Extract the path after /api/academic-exams and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/academic-exams', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/academic-exams${pathAfterApi}`,
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

// FeeManagement Service proxy routes for student fees
router.use('/api/fee-management', (req, res) => {
  console.log('Gateway: Proxying FeeManagement service request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/fee-management and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/fee-management', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${FEE_MANAGEMENT_SERVICE_URL}/api${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: FeeManagement Service Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: FeeManagement service response status:', response.status);
      console.log('Gateway: Fee management response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: FeeManagement Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Fee management service error', details: error.message }
      );
    });
});

// FeeManagement Service proxy routes for student fees by user ID
router.use('/api/student-fees', (req, res) => {
  console.log('Gateway: Proxying student-fees request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/student-fees and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/student-fees', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${FEE_MANAGEMENT_SERVICE_URL}/api/student-fees${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: FeeManagement Student Fees Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: FeeManagement student-fees response status:', response.status);
      console.log('Gateway: Student fees response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: FeeManagement student-fees proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Fee management service error', details: error.message }
      );
    });
});

// Legacy AdminService proxy routes for fee templates
router.use('/api/fee-templates', (req, res) => {
  console.log('Gateway: Proxying AdminService fee-templates request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/fee-templates and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/fee-templates', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/fee-templates${pathAfterApi}`,
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
        s.user_id,
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
        t.user_id,
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
      
      const userId = uuidv4();
      const hashedPassword = await bcrypt.hash(password, 10);
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
// AdminService proxy routes for leave management
router.use('/api/leaves', (req, res) => {
  console.log('Gateway: Proxying AdminService leaves request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/leaves and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/leaves', '').trim();
  
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/leaves${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService leaves Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService leaves response status:', response.status);
      console.log('Gateway: Leaves response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService leaves proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// ========== WEBSOCKET PROXY FOR STUDENT NOTIFICATIONS ==========
// WebSocket proxy endpoint for students to receive real-time notifications
router.get('/ws/students', (req, res) => {
  console.log('🔌 Gateway: Student WebSocket connection request');
  
  // Verify JWT token for WebSocket connection
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    console.log('⚠️ Gateway: WebSocket connection rejected - no token');
    return res.status(401).json({
      error: 'Authentication token required for WebSocket connection'
    });
  }
  
  try {
    // Verify JWT token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log('⚠️ Gateway: WebSocket connection rejected - invalid token');
        return res.status(403).json({
          error: 'Invalid or expired token for WebSocket connection'
        });
      }
      
      console.log('✅ Gateway: WebSocket connection authorized for user:', user.role);
      
      // Redirect to ClassesService WebSocket endpoint
      const targetUrl = `${CLASSES_SERVICE_URL}/ws`;
      console.log(`🔄 Redirecting to ClassesService WebSocket: ${targetUrl}`);
      
      // For actual WebSocket proxy, you would use a WebSocket proxy library like 'ws-proxy'
      // For now, provide information about direct connection
      res.json({
        message: 'WebSocket connection authorized',
        redirect_info: 'Connect directly to ClassesService WebSocket endpoint',
        websocket_endpoint: `${CLASSES_SERVICE_URL}/ws`,
        client_instruction: 'Use student UUID to register via WebSocket',
        example: {
          connection_url: `${CLASSES_SERVICE_URL}/ws`,
          registration_message: {
            type: 'register',
            studentId: 'your-student-uuid'
          }
        }
      });
    });
  } catch (error) {
    console.error('❌ Gateway: WebSocket auth error:', error);
    res.status(500).json({
      error: 'WebSocket authentication failed'
    });
  }
});

// WebSocket status endpoint for monitoring
router.get('/ws/status', (req, res) => {
  res.json({
    message: 'WebSocket service available',
    endpoints: {
      direct: 'ws://localhost:8004/ws (ClassesService)',
      gateway: 'ws://localhost:8000/ws/students (Gateway - for auth)',
    },
    client_info: 'Students should connect directly to ClassesService WebSocket endpoint for real-time notifications',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;

