import express from "express";
import cors from 'cors';
import dotenv from 'dotenv';
import routes from "./router.js";

dotenv.config();

const app = express();

// Allowed exact domains
const allowedOrigins = [
  'http://localhost:3000',
  'https://localhost:3000',
  'https://schooling-client.vercel.app',
  'https://servercode-gateway-production.up.railway.app',
  'https://schooling-client-3p2hbuhdi-maheshs-projects-ba0e9f94.vercel.app',
  'https://schooling-client.vercel.app'
];

// Allow any *.vercel.app
const vercelRegex = /\.vercel\.app$/;

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || vercelRegex.test(origin)) {
      return callback(null, true);
    }
    console.log('❌ Blocked by CORS:', origin);
    return callback(new Error('CORS NOT ALLOWED'));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ]
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // IMPORTANT

app.use(express.json());
app.use("/", routes);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});
