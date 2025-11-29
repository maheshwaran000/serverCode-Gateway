import express from "express";
import cors from 'cors';
import dotenv from 'dotenv';
import routes from "./router.js";

dotenv.config();

const app = express();

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:3000', // Development
    'https://localhost:3000',
    'https://schooling-client.vercel.app',// HTTPS Development
    'https://servercode-gateway-production.up.railway.app',
    // Production frontend domains
    'https://schooling-client-3p2hbuhdi-maheshs-projects-ba0e9f94.vercel.app',
    'https://schooling-client.vercel.app',
    // Allow all Vercel domains for flexibility
    /\.vercel\.app$/
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-User-Role'],
  exposedHeaders: []
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

// Routes
app.use("/", routes);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});
