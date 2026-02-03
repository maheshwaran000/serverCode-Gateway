const { Pool } = require('pg');
const dotenv = require('dotenv');
const path = require('path');

// __dirname equivalent in CommonJS already exists, no need for import.meta.url
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 20,
  min: 2,
  idleTimeoutMillis: 60000,
  connectionTimeoutMillis: 15000,
  statement_timeout: 30000,
  query_timeout: 30000,
  keepAlive: true,
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false,
    servername: process.env.DB_HOST
  } : false,
});

console.log("Gateway Database Pool Configuration:", {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  ssl: process.env.DB_SSL
});

pool.on('connect', () => {
  console.log('✅ Gateway: Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Gateway: Database connection error:', err);
  process.exit(-1);
});

pool.on('acquire', () => {
  console.log('🔄 Gateway: Connection acquired from pool');
});

pool.on('release', () => {
  console.log('🔄 Gateway: Connection released back to pool');
});

module.exports = pool;
