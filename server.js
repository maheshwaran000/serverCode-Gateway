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
    'https://localhost:3000', // HTTPS Development
    // Add your production frontend domain here if needed
  ],
  credentials: true,
  optionsSuccessStatus: 200
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
