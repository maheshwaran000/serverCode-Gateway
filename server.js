const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const routes = require("./router.js");


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

// URL cleaning middleware to handle encoded newlines and other issues
app.use((req, res, next) => {
  // Clean the originalUrl to remove encoded newlines and other problematic characters
  const originalUrl = req.originalUrl;
  const cleanedUrl = originalUrl.replace(/%0A|%0D/g, ''); // Remove encoded newlines and carriage returns
  
  if (originalUrl !== cleanedUrl) {
    console.log(`Gateway: Cleaned URL from "${originalUrl}" to "${cleanedUrl}"`);
    // Modify the request URL for route matching
    req.originalUrl = cleanedUrl;
    req.url = cleanedUrl;
  }
  
  next();
});

// Routes
app.use("/", routes);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});
