const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const pool = require('./config/database.js');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');


// Environment-based service URLs
// const isDevelopment = process.env.NODE_ENV !== 'production';

// Development URLs (local services)
// const AUTH_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8001/api/auth'
//   : 'https://servercode-authservice-production.up.railway.app/api/auth';

// const BRANCH_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8002/api/branches'
//   : 'https://servercode-branchservice-production.up.railway.app/api/branches';

// const USER_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8003/api/users'
//   : 'https://servercode-userservice-production.up.railway.app/api/users';

// const CLASSES_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8004'
//   : 'https://servercodeclassesservice-production.up.railway.app';

// const HRMS_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8005/api'
//   : 'https://servercode-hrmsservice-production.up.railway.app/api';

// const ADMIN_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8006'
//   : 'https://servercode-adminservice-production.up.railway.app';

// const FEE_MANAGEMENT_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8007'
//   : 'https://servercodefeemanagement-production.up.railway.app';

// const EXAMINATION_SERVICE_URL = isDevelopment
//   ? 'http://localhost:8009'
//   : 'https://servercodeexamination-production.up.railway.app';

// const PUBLIC_ADMISSIONS_SERVICE_URL = isDevelopment
//   ? 'http://localhost:3008/public'
//   : 'https://servercode-publicadmissions-production.up.railway.app/public';

const AUTH_SERVICE_URL = 'http://localhost:8001/api/auth';
const BRANCH_SERVICE_URL = 'http://localhost:8002/api/branches';
const USER_SERVICE_URL = 'http://localhost:8003/api/users';
const CLASSES_SERVICE_URL = 'http://localhost:8004';
const HRMS_SERVICE_URL = 'http://localhost:8005/api';
const ADMIN_SERVICE_URL = 'http://localhost:8006';
const FEE_MANAGEMENT_SERVICE_URL = 'http://localhost:8007';
const EXAMINATION_SERVICE_URL = 'http://localhost:8009';
const PUBLIC_ADMISSIONS_SERVICE_URL = 'http://localhost:3008/public';


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
  // Skip authentication for public routes
  if (req.originalUrl.includes('/api/examination/sessions') ||
    req.originalUrl.includes('/api/public/admissions')) {
    console.log(`🔓 Public route accessed: ${req.method} ${req.originalUrl}`);
    req.user = { id: 'public-user', role: 'public' };
    return next();
  }

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
router.post('/api/auth/login', async (req, res) => {
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

router.get('/api/auth/verify', authenticateToken, async (req, res) => {
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

// Reset password for any user by userid
router.post('/api/auth/reset-password', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Reset password request:', req.body);
    const response = await axios.post(`${AUTH_SERVICE_URL}/reset-password`, req.body, {
      headers: { Authorization: req.headers.authorization }
    });
    console.log('Gateway: Reset password response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Reset password proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Create admin user (for branch creators)
router.post('/api/auth/create-admin', authenticateToken, async (req, res) => {
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

// Create custom admin user with module permissions
router.post('/users/create-admin-user', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Create custom admin request:', req.body);

    const { userid, password, name, phone, branchId, role, modules } = req.body;

    // Validate required fields
    if (!userid || !password || !name || !phone || !branchId || !role) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check if userid already exists
      const existingUser = await client.query('SELECT id FROM users WHERE userid = $1', [userid]);
      if (existingUser.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          success: false,
          error: 'User ID already exists'
        });
      }

      // Generate UUID for new user
      const userId = uuidv4();
      const hashedPassword = await bcrypt.hash(password, 10);
      const email = `${userid.toLowerCase()}@eims.edu`;

      // Insert user
      const userResult = await client.query(`
        INSERT INTO users (id, userid, email, role, name, phone, branch_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        RETURNING id, userid, email, role, name
      `, [userId, userid, email, role, name, phone, branchId]);

      // Insert password
      await client.query(`
        INSERT INTO user_auth (user_id, password_hash, created_at)
        VALUES ($1, $2, NOW())
      `, [userId, hashedPassword]);

      // Insert module permissions if modules are provided
      if (modules && modules.length > 0) {
        for (const moduleCode of modules) {
          await client.query(`
            INSERT INTO branch.admin_modules (admin_user_id, module_code, branch_id, granted_by, granted_at)
            VALUES ($1, $2, $3, $4, NOW())
          `, [userId, moduleCode, branchId, req.user.userId]);
        }
      }

      await client.query('COMMIT');

      console.log(`✅ Custom admin created successfully: ${userid}`);

      res.json({
        success: true,
        message: 'Custom admin created successfully',
        user: userResult.rows[0],
        email: email,
        modules_count: modules ? modules.length : 0
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Error creating custom admin:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create custom admin',
      details: error.message
    });
  }
});

// Get admin modules
router.get('/api/admins/:adminId/modules', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Get admin modules request:', req.params.adminId);

    const { adminId } = req.params;

    const query = `
      SELECT 
        am.module_code,
        m.module_name,
        m.description,
        m.category,
        am.granted_at,
        am.is_active
      FROM branch.admin_modules am
      LEFT JOIN public.modules m ON am.module_code = m.module_code
      WHERE am.admin_user_id = $1
      AND am.is_active = true
      ORDER BY m.category, m.module_name
    `;

    const result = await pool.query(query, [adminId]);

    res.json({
      success: true,
      data: result.rows
    });

  } catch (error) {
    console.error('Error fetching admin modules:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch admin modules',
      details: error.message
    });
  }
});

// Update admin modules
router.put('/api/admins/:adminId/modules', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Update admin modules request:', req.params.adminId, req.body);

    const { adminId } = req.params;
    const { modules } = req.body;

    if (!modules || !Array.isArray(modules)) {
      return res.status(400).json({
        success: false,
        error: 'Modules array is required'
      });
    }

    // Get user's branch for validation
    const userResult = await pool.query('SELECT branch_id FROM users WHERE id = $1', [adminId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Admin user not found'
      });
    }

    const branchId = userResult.rows[0].branch_id;

    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Remove existing module permissions
      await client.query('DELETE FROM branch.admin_modules WHERE admin_user_id = $1', [adminId]);

      // Add new module permissions
      for (const moduleCode of modules) {
        await client.query(`
          INSERT INTO branch.admin_modules (admin_user_id, module_code, branch_id, granted_by, granted_at)
          VALUES ($1, $2, $3, $4, NOW())
        `, [adminId, moduleCode, branchId, req.user.userId]);
      }

      await client.query('COMMIT');

      console.log(`✅ Admin modules updated successfully for admin: ${adminId}`);

      res.json({
        success: true,
        message: 'Admin modules updated successfully',
        modules_count: modules.length
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Error updating admin modules:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update admin modules',
      details: error.message
    });
  }
});

// Create student user
router.post('/api/auth/create-student', authenticateToken, async (req, res) => {
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

// Bulk create students
router.post('/api/auth/bulk-create-students', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Bulk create students request:', req.body?.students?.length || 0);

    const response = await axios.post(
      `${AUTH_SERVICE_URL}/bulk-create-students`,
      req.body,
      { headers: { Authorization: req.headers.authorization } }
    );

    console.log('Gateway: Bulk create students response:', response.data);
    return res.json(response.data);
  } catch (error) {
    console.error(
      'Gateway: Bulk create students proxy error:',
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

// Get parent's children
router.get('/api/auth/parents/:parentId/children', authenticateToken, async (req, res) => {
  try {
    const { parentId } = req.params;
    console.log(`Gateway: Get parents children request for parentId: ${parentId}`);

    const response = await axios.get(
      `${AUTH_SERVICE_URL}/parents/${parentId}/children`,
      { headers: { Authorization: req.headers.authorization } }
    );

    console.log('Gateway: Get parents children response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Get parents children proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Auth service error' });
  }
});

// Public Admissions Service proxy routes (no auth required)
// router.use('/api/public', (req, res) => {
//   console.log('Gateway: Proxying Public Admissions request:', req.method, req.originalUrl);

//   const forwardedHeaders = {
//     'content-type': req.headers['content-type'],
//     'accept': req.headers.accept,
//     'user-agent': req.headers['user-agent']
//   };

//   // Extract the path after /api/public and append to base URL
//   const pathAfterApi = req.originalUrl.replace('/api/public', '').trim();

//   const axiosConfig = {
//     method: req.method,
//     url: `${PUBLIC_ADMISSIONS_SERVICE_URL}${pathAfterApi}`,
//     headers: forwardedHeaders,
//     data: req.method !== 'GET' ? req.body : undefined,
//     timeout: 60000,
//     validateStatus: () => true
//   };

//   console.log('Gateway: Public Admissions Axios config:', {
//     method: axiosConfig.method,
//     url: axiosConfig.url,
//     hasData: !!axiosConfig.data
//   });

//   axios(axiosConfig)
//     .then(response => {
//       console.log('Gateway: Public Admissions response status:', response.status);
//       res.status(response.status).json(response.data);
//     })
//     .catch(error => {
//       console.error('Gateway: Public Admissions proxy error:', {
//         message: error.message,
//         status: error.response?.status,
//         data: error.response?.data
//       });
//       res.status(error.response?.status || 500).json(
//         error.response?.data || { error: 'Public Admissions service error', details: error.message }
//       );
//     });
// });
// Public OTP endpoints for branch creation (no auth required)
router.post('/api/send-email-otp', async (req, res) => {
  try {
    console.log('Gateway: Proxying send-email-otp to BranchService:', req.body);
    const response = await axios.post(`${BRANCH_SERVICE_URL.replace('/branches', '')}/send-email-otp`, req.body);
    console.log('Gateway: Send email OTP response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Send email OTP proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Branch service error' });
  }
});

router.post('/api/verify-email-otp', async (req, res) => {
  try {
    console.log('Gateway: Proxying verify-email-otp to BranchService:', req.body);
    const response = await axios.post(`${BRANCH_SERVICE_URL.replace('/branches', '')}/verify-email-otp`, req.body);
    console.log('Gateway: Verify email OTP response:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Gateway: Verify email OTP proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Branch service error' });
  }
});

// Public Admissions Service proxy routes (no auth required for public routes)
router.use('/public/admissions', async (req, res) => {
  console.log(
    'Gateway: Proxying Public Admissions request (public path):',
    req.method,
    req.originalUrl
  );

  try {
    // Extract the path after /public and append to service URL
    const pathAfterPublic = req.originalUrl.replace('/public', '').trim();

    const response = await axios({
      method: req.method,
      url: `${PUBLIC_ADMISSIONS_SERVICE_URL}${pathAfterPublic}`,
      headers: {
        'content-type': req.headers['content-type'] || 'application/json',
        'accept': req.headers.accept || 'application/json',
        'user-agent': req.headers['user-agent'],
        'authorization': req.headers.authorization // Include auth for protected endpoints
      },
      data: req.method !== 'GET' && req.method !== 'DELETE' ? req.body : undefined,
      timeout: 60000
    });

    console.log(
      'Gateway: Public Admissions response status (public path):',
      response.status
    );

    return res.status(response.status).json(response.data);

  } catch (error) {
    console.error('Gateway: Public Admissions proxy error (public path):', {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data
    });

    return res.status(error.response?.status || 500).json(
      error.response?.data || {
        success: false,
        error: 'Public Admissions service error'
      }
    );
  }
});

// Public Admissions Service proxy routes (no auth required for public routes)
router.use('/api/public/admissions', async (req, res) => {
  console.log(
    'Gateway: Proxying Public Admissions request:',
    req.method,
    req.originalUrl
  );

  try {
    // Extract the path after /api/public and append to service URL
    const pathAfterApi = req.originalUrl.replace('/api/public', '').trim();

    const response = await axios({
      method: req.method,
      url: `${PUBLIC_ADMISSIONS_SERVICE_URL}${pathAfterApi}`,
      headers: {
        'content-type': req.headers['content-type'] || 'application/json',
        'accept': req.headers.accept || 'application/json',
        'user-agent': req.headers['user-agent'],
        'authorization': req.headers.authorization // Include auth for protected endpoints
      },
      data: req.method !== 'GET' && req.method !== 'DELETE' ? req.body : undefined,
      timeout: 60000
    });

    console.log(
      'Gateway: Public Admissions response status:',
      response.status
    );

    return res.status(response.status).json(response.data);

  } catch (error) {
    console.error('Gateway: Public Admissions proxy error:', {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data
    });

    return res.status(error.response?.status || 500).json(
      error.response?.data || {
        success: false,
        error: 'Public Admissions service error'
      }
    );
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
router.use('/api/allocate-room', (req, res) => {
  console.log('Gateway: Proxying allocate-room request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/allocate-room and append to allocate-room
  const pathAfterApi = req.originalUrl.replace('/api/allocate-room', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/allocate-room`,
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
// Get all branches with aggregated statistics
router.get('/api/branches/with-stats', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Fetching branches with statistics');

    // Get all branches
    const branchesQuery = `
      SELECT id, branch_code, branch_name, branch_type, location, principal_name,
             contact_email, contact_phone, address, status, created_at
      FROM superadmin.branches
      WHERE status = 'Active'
      ORDER BY branch_name
    `;

    const branchesResult = await pool.query(branchesQuery);
    const branches = branchesResult.rows;

    // Get user counts for each branch
    const userCountsQuery = `
      SELECT
        branch_id,
        role,
        COUNT(*) as count
      FROM public.users
      WHERE branch_id IS NOT NULL
        AND role IN ('student', 'teacher', 'staff')
      GROUP BY branch_id, role
    `;

    const userCountsResult = await pool.query(userCountsQuery);
    const userCounts = userCountsResult.rows;

    // Organize counts by branch
    const branchStats = {};
    userCounts.forEach(count => {
      if (!branchStats[count.branch_id]) {
        branchStats[count.branch_id] = {
          students: 0,
          teachers: 0,
          staff: 0
        };
      }
      branchStats[count.branch_id][count.role + 's'] = parseInt(count.count);
    });

    // Combine branches with their stats
    const branchesWithStats = branches.map(branch => ({
      ...branch,
      totalStudents: branchStats[branch.id]?.students || 0,
      totalTeachers: branchStats[branch.id]?.teachers || 0,
      totalStaff: branchStats[branch.id]?.staff || 0
    }));

    // Calculate overall totals
    const overallTotals = branchesWithStats.reduce((acc, branch) => ({
      totalBranches: branches.length,
      totalStudents: acc.totalStudents + branch.totalStudents,
      totalTeachers: acc.totalTeachers + branch.totalTeachers,
      totalStaff: acc.totalStaff + branch.totalStaff
    }), { totalBranches: 0, totalStudents: 0, totalTeachers: 0, totalStaff: 0 });

    const response = {
      success: true,
      data: {
        branches: branchesWithStats,
        summary: overallTotals
      }
    };

    console.log('✅ Branches with stats retrieved successfully');
    res.json(response);
  } catch (error) {
    console.error('Error fetching branches with stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch branches with statistics',
      details: error.message
    });
  }
});

// Module API routes - proxy to BranchService
router.use('/api/modules', (req, res) => {
  console.log('Gateway: Proxying modules request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Handle branch-specific module requests
  if (req.originalUrl.match(/\/api\/modules\/branches\/([^/]+)/)) {
    console.log('Gateway: Handling branch modules request');

    const branchIdMatch = req.originalUrl.match(/\/api\/modules\/branches\/([^/]+)/);
    const branchId = branchIdMatch[1];

    // Convert to BranchService format: /branches/{id}/modules
    const pathAfterBranch = req.originalUrl.replace(`/api/modules/branches/${branchId}`, '').trim();
    const targetUrl = `${BRANCH_SERVICE_URL}/branches/${branchId}/modules${pathAfterBranch}`;

    console.log('Gateway: Converting branch modules request to:', targetUrl);

    const axiosConfig = {
      method: req.method,
      url: targetUrl,
      headers: forwardedHeaders,
      data: req.method !== 'GET' ? req.body : undefined,
      timeout: 60000,
      validateStatus: () => true
    };

    console.log('Gateway: Branch Modules API Axios config:', {
      method: axiosConfig.method,
      url: axiosConfig.url,
      hasAuth: !!axiosConfig.headers.authorization,
      hasData: !!axiosConfig.data
    });

    axios(axiosConfig)
      .then(response => {
        console.log('✅ Gateway: Branch Modules API response status:', response.status);
        console.log('📋 Gateway: Branch Modules API response data:', response.data);
        res.status(response.status).json(response.data);
      })
      .catch(error => {
        console.error('❌ Gateway: Branch Modules API proxy error:', {
          message: error.message,
          status: error.response?.status,
          data: error.response?.data
        });
        res.status(error.response?.status || 500).json(
          error.response?.data || { error: 'Branch Modules service error', details: error.message }
        );
      });
    return;
  }

  // Handle regular module requests (for all available modules)
  const pathAfterApi = req.originalUrl.replace('/api/modules', '').trim();

  // Remove /api/branches from BRANCH_SERVICE_URL and add correct modules path
  const baseUrl = BRANCH_SERVICE_URL.replace('/api/branches', '');
  const axiosConfig = {
    method: req.method,
    url: `${baseUrl}/api/modules${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Modules API Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('✅ Gateway: Modules API response status:', response.status);
      console.log('📋 Gateway: Modules API response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('❌ Gateway: Modules API proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Modules service error', details: error.message }
      );
    });
});

// Branch Service proxy routes with special handling for admin endpoints
router.use('/api/branches', (req, res) => {
  console.log('Gateway: Processing branch request:', req.method, req.originalUrl);

  // Skip specific routes that are handled elsewhere
  if (req.originalUrl.includes('/with-stats')) {
    console.log('Gateway: Skipping /with-stats route - handled by specific endpoint');
    return res.status(404).json({ error: 'Route not found in proxy' });
  }

  // Handle module endpoints specifically for branches
  if (req.originalUrl.match(/\/api\/branches\/[^/]+\/modules/)) {
    console.log('Gateway: Handling branch modules request directly');

    // Extract branch ID from URL
    const branchIdMatch = req.originalUrl.match(/\/api\/branches\/([^/]+)\/modules/);
    if (!branchIdMatch) {
      return res.status(400).json({
        success: false,
        error: 'Invalid branch ID format'
      });
    }

    const branchId = branchIdMatch[1];

    // Convert to BranchService format and handle directly
    const pathAfterBranch = req.originalUrl.replace(req.originalUrl.match(/\/api\/branches\/[^/]+\/modules/)[0], '').trim();
    const targetUrl = `${BRANCH_SERVICE_URL}/${branchId}/modules${pathAfterBranch}`;

    console.log('Gateway: Converting branch modules request to:', targetUrl);

    const forwardedHeaders = {
      'authorization': req.headers.authorization,
      'content-type': req.headers['content-type'],
      'accept': req.headers.accept,
      'user-agent': req.headers['user-agent']
    };

    const axiosConfig = {
      method: req.method,
      url: targetUrl,
      headers: forwardedHeaders,
      data: req.method !== 'GET' ? req.body : undefined,
      timeout: 60000,
      validateStatus: () => true
    };

    console.log('Gateway: Branch Modules API Axios config:', {
      method: axiosConfig.method,
      url: axiosConfig.url,
      hasAuth: !!axiosConfig.headers.authorization,
      hasData: !!axiosConfig.data
    });

    axios(axiosConfig)
      .then(response => {
        console.log('✅ Gateway: Branch Modules API response status:', response.status);
        console.log('📋 Gateway: Branch Modules API response data:', response.data);
        res.status(response.status).json(response.data);
      })
      .catch(error => {
        console.error('❌ Gateway: Branch Modules API proxy error:', {
          message: error.message,
          status: error.response?.status,
          data: error.response?.data
        });
        res.status(error.response?.status || 500).json(
          error.response?.data || { error: 'Branch Modules service error', details: error.message }
        );
      });
    return;
  }

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
  const pathAfterApi = req.originalUrl.replace(`/api/classes/${req.params.id}/students`, '').trim();

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

// Classes Service proxy routes - Generic (must come LAST after all specific routes)
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

// Classes Service proxy routes for comprehensive timetable management (comes AFTER generic classes route to avoid conflicts)
router.use('/api/timetables', (req, res) => {
  console.log('Gateway: Proxying Classes timetables request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/timetables and construct target URL
  const pathAfterTimetables = req.originalUrl.replace('/api/timetables', '').trim();
  const targetUrl = `${CLASSES_SERVICE_URL}/api/classes/timetables${pathAfterTimetables}`;

  const axiosConfig = {
    method: req.method,
    url: targetUrl,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service timetables Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service timetables response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service timetables proxy error:', {
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

// Public endpoint for academic years (no authentication required)
router.get('/api/academic-years/all', (req, res) => {
  console.log('Gateway: Public academic-years request (no auth required)');

  const forwardedHeaders = {
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: 'GET',
    url: `${CLASSES_SERVICE_URL}/api/classes/academic-years/all`,
    headers: forwardedHeaders,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Public academic-years Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Public academic-years response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Public academic-years proxy error:', {
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
// AdminService Bulk Attendance - MUST come before generic /:id route of ClassesService
router.use('/api/attendance/bulk', (req, res) => {
  console.log('Gateway: Proxying AdminService attendance bulk request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract query parameters
  const pathAfterApi = req.originalUrl.replace('/api/attendance/bulk', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/attendance/bulk${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService attendance bulk Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url
  });

  axios(axiosConfig)
    .then(response => {
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService attendance bulk proxy error:', error.message);
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'AdminService error', details: error.message }
      );
    });
});

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

// AdminService proxy routes for holidays
router.use('/api/holidays', (req, res) => {
  console.log('Gateway: Proxying AdminService holidays request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/holidays and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/holidays', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/holidays${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService holidays Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService holidays response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService holidays proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
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

// AdminService proxy routes for driver app
router.use('/api/driver', (req, res) => {
  console.log('Gateway: Proxying AdminService driver request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/driver and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/driver', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/driver${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService driver Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService driver proxy error:', error.message);
      if (error.response) {
        res.status(error.response.status).json(error.response.data);
      } else {
        res.status(500).json({ error: 'Gateway error connecting to AdminService' });
      }
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

// AdminService proxy route for student hostel details
router.use('/api/student-hostel', (req, res) => {
  console.log('Gateway: Proxying AdminService student-hostel request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const pathAfterApi = req.originalUrl.replace('/api/student-hostel', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/student-hostel${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  axios(axiosConfig)
    .then(response => {
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// BranchService proxy route for student transport details
router.use('/api/student-transport', (req, res) => {
  console.log('Gateway: Proxying BranchService student-transport request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const pathAfterApi = req.originalUrl.replace('/api/student-transport', '').trim();

  const axiosConfig = {
    method: req.method,
    // BRANCH_SERVICE_URL is already .../api/branches
    url: `${BRANCH_SERVICE_URL}/student-transport${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  axios(axiosConfig)
    .then(response => {
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Branch service error', details: error.message }
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

// AdminService proxy routes for notices
router.use('/api/notices', (req, res) => {
  console.log('Gateway: Proxying AdminService notices request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/notices and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/notices', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/notices${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService notices Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService notices response status:', response.status);
      console.log('Gateway: Notices response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService notices proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for custom exams create
router.use('/api/create-exam', (req, res) => {
  console.log('Gateway: Proxying AdminService create-exam request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/create-exam`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService create-exam Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService create-exam response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService create-exam proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for custom exams get
router.use('/api/get', (req, res) => {
  console.log('Gateway: Proxying AdminService get request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract query parameters
  const queryString = Object.keys(req.query).length > 0 ? '?' + new URLSearchParams(req.query).toString() : '';

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/get${queryString}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService get Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService get response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService get proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// AdminService proxy routes for grades management
router.use('/api/grades', (req, res) => {
  console.log('Gateway: Proxying AdminService grades request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Use req.originalUrl to forward full path and query params
  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}${req.originalUrl}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService grades Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService grades response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService grades proxy error:', {
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

// Examination Service proxy routes - both /api and legacy /examination
router.use(['/api/examination', '/examination'], (req, res) => {
  console.log('Gateway: Proxying Examination service request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/examination or /examination and append to base URL
  const pathAfterApi = req.originalUrl.replace(/^\/(?:api\/)?examination/, '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${EXAMINATION_SERVICE_URL}/api/examination${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Examination Service Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Examination service response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Examination Service proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Examination service error', details: error.message }
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
// Staff Management Endpoints
router.get('/api/staff', async (req, res) => {
  try {
    console.log('Gateway: Fetching all staff');

    // Extract user details from the request
    const { role } = req.user;
    const branchId = req.user.branchId || req.user.branch_id;

    let queryParams = [];
    let whereClause = '';

    // Apply branch filtering for non-superadmin users
    // If user has a branchId and is not a super-user, filter by branch
    if (role !== 'superadmin' && role !== 'access_manager' && branchId) {
      whereClause = 'WHERE s.branch_id = $1';
      queryParams.push(branchId);
      console.log(`Gateway: Filtering staff for branch ${branchId}`);
    }

    const query = `
      SELECT
        s.user_id as id,
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
        b.branch_name,
        s.branch_id
      FROM branch.staff s
      LEFT JOIN users u ON s.user_id = u.id
      LEFT JOIN superadmin.branches b ON s.branch_id = b.id
      ${whereClause}
      ORDER BY s.created_at DESC
    `;

    const result = await pool.query(query, queryParams);

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
        s.user_id as id,
        u.userid,
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
router.get('/api/users/superadmins', authenticateToken, async (req, res) => {
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

router.get('/api/users/branch-level-managers', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Fetching branch level managers');

    const query = `
      SELECT id, userid, name, email, role, created_at
      FROM users
      WHERE role = 'branchlevel_manager'
      ORDER BY created_at DESC
    `;

    const result = await pool.query(query);

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Error fetching branch level managers:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch branch level managers',
      details: error.message
    });
  }
});

router.get('/api/users/access-level-managers', authenticateToken, async (req, res) => {
  try {
    console.log('Gateway: Fetching access level managers');

    const query = `
      SELECT id, userid, name, email, role, created_at
      FROM users
      WHERE role = 'access_manager'
      ORDER BY created_at DESC
    `;

    const result = await pool.query(query);

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Error fetching access level managers:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch access level managers',
      details: error.message
    });
  }
});

// Teacher Management Endpoints
// Teacher Management Endpoints
router.get('/api/teachers', async (req, res) => {
  try {
    console.log('Gateway: Fetching all teachers');

    // Extract user details from the request
    const { role } = req.user;
    const branchId = req.user.branchId || req.user.branch_id;

    let queryParams = [];
    let whereClause = '';

    // Apply branch filtering for non-superadmin users
    if (role !== 'superadmin' && role !== 'access_manager' && branchId) {
      whereClause = 'WHERE t.branch_id = $1';
      queryParams.push(branchId);
      console.log(`Gateway: Filtering teachers for branch ${branchId}`);
    }

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
        b.branch_name,
        t.branch_id
      FROM branch.teachers t
      LEFT JOIN users u ON t.user_id = u.id
      LEFT JOIN superadmin.branches b ON t.branch_id = b.id
      ${whereClause}
      ORDER BY t.created_at DESC
    `;

    const result = await pool.query(query, queryParams);

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
        t.user_id as id,
        u.userid,
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


// Driver Profile Endpoint (Mirroring Teacher Profile)
router.get('/api/drivers/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log('Gateway: Fetching driver by user ID:', userId);

    const query = `
      SELECT
        u.id, 
        u.userid, 
        u.name, 
        u.email, 
        u.phone, 
        u.address, 
        u.role,
        u.joining_date,
        u.status,
        u.salary as basic_salary,
        br.vehicle_number,
        br.route_name,
        br.route_number,
        b.branch_name
      FROM users u
      LEFT JOIN branch.bus_routes br ON u.userid = br.driver_user_id AND br.status = 'active'
      LEFT JOIN superadmin.branches b ON u.branch_id = b.id
      WHERE u.id = $1 AND u.role = 'driver'
    `;

    const result = await pool.query(query, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Driver not found'
      });
    }

    const driver = result.rows[0];

    res.json({
      success: true,
      data: {
        ...driver,
        department: 'Transport',
        designation: 'Driver',
        qualification: 'N/A',
        experience_years: 'N/A'
      }
    });
  } catch (error) {
    console.error('Error fetching driver by user ID:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch driver',
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

// Admin API routes for leave requests (Proxy to AdminService)
router.use('/api/admin/leave-requests', async (req, res) => {
  console.log('Gateway: Proxying leave request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  try {
    // Construct target URL
    // req.url is relative to mount point: /api/admin/leave-requests
    // e.g. if originalUrl is /api/admin/leave-requests, req.url is /
    // e.g. if originalUrl is /api/admin/leave-requests/top, req.url is /top

    // We want target: ADMIN_SERVICE_URL/api/leave-requests + req.url
    const path = req.url === '/' ? '' : req.url;
    const targetUrl = `${ADMIN_SERVICE_URL}/api/leave-requests${path}`;

    console.log('Target URL:', targetUrl);

    const response = await axios({
      method: req.method,
      url: targetUrl,
      headers: forwardedHeaders,
      data: req.method !== 'GET' && req.method !== 'DELETE' ? req.body : undefined
    });

    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Gateway: Leave request proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Admin service error' });
  }
});


// Admin API routes for complaints (Proxy to AdminService)
router.use('/api/admin/complaints', async (req, res) => {
  console.log('Gateway: Proxying complaint to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  try {
    // Target: ADMIN_SERVICE_URL/api/complaints + req.url
    const path = req.url === '/' ? '' : req.url;
    const targetUrl = `${ADMIN_SERVICE_URL}/api/complaints${path}`;

    const response = await axios({
      method: req.method,
      url: targetUrl,
      headers: forwardedHeaders,
      data: req.method !== 'GET' && req.method !== 'DELETE' ? req.body : undefined
    });

    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Gateway: Complaint proxy error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json(error.response?.data || { error: 'Admin service error' });
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

// AdminService proxy routes for attendance management
router.use('/api/attendance', (req, res) => {
  console.log('Gateway: Proxying AdminService attendance request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/attendance and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/attendance', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/attendance${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService attendance Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService attendance response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService attendance proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});
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

// AdminService proxy routes for library management
router.use('/api/library', (req, res) => {
  console.log('Gateway: Proxying AdminService library request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/library and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/library', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/library${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService library Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService library response status:', response.status);
      console.log('Gateway: Library response data:', response.data);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService library proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// ClassesService proxy routes for subjects
router.use('/api/subjects', (req, res) => {
  console.log('Gateway: Proxying subjects request to ClassesService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/subjects and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/subjects', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/subjects${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: ClassesService subjects Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: ClassesService subjects response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: ClassesService subjects proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
      );
    });
});

// AdminService proxy routes for department-incharges
router.use('/api/department-incharges', (req, res) => {
  console.log('Gateway: Proxying department-incharges request to AdminService:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent']
  };

  // Extract the path after /api/department-incharges and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/department-incharges', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${ADMIN_SERVICE_URL}/api/department-incharges${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: AdminService department-incharges Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: AdminService department-incharges response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: AdminService department-incharges proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Admin service error', details: error.message }
      );
    });
});

// ========== SYLLABUS MANAGEMENT ENDPOINTS ==========

// Classes Service proxy routes for syllabus management
router.use('/api/syllabus', (req, res) => {
  console.log('Gateway: Proxying Classes syllabus request:', req.method, req.originalUrl);

  const forwardedHeaders = {
    'authorization': req.headers.authorization,
    'content-type': req.headers['content-type'],
    'accept': req.headers.accept,
    'user-agent': req.headers['user-agent'],
    'x-user-role': req.headers['x-user-role']
  };

  // Extract the path after /api/syllabus and append to base URL
  const pathAfterApi = req.originalUrl.replace('/api/syllabus', '').trim();

  const axiosConfig = {
    method: req.method,
    url: `${CLASSES_SERVICE_URL}/api/classes/syllabus${pathAfterApi}`,
    headers: forwardedHeaders,
    data: req.method !== 'GET' ? req.body : undefined,
    timeout: 60000,
    validateStatus: () => true
  };

  console.log('Gateway: Classes Service syllabus Axios config:', {
    method: axiosConfig.method,
    url: axiosConfig.url,
    hasAuth: !!axiosConfig.headers.authorization,
    hasData: !!axiosConfig.data
  });

  axios(axiosConfig)
    .then(response => {
      console.log('Gateway: Classes service syllabus response status:', response.status);
      res.status(response.status).json(response.data);
    })
    .catch(error => {
      console.error('Gateway: Classes Service syllabus proxy error:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data
      });
      res.status(error.response?.status || 500).json(
        error.response?.data || { error: 'Classes service error', details: error.message }
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
