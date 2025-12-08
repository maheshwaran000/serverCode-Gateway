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
  connectionTimeoutMillis: 10000,
  statement_timeout: 30000,
  query_timeout: 30000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
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

module.exports = pool;
