import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import authRoutes from './auth/routes';
import { config } from './config/env';

const app = express();

// Basic security headers
app.use(helmet());

// CORS – allow your Next.js origin
app.use(cors({
  origin: config.frontendOrigin, // e.g. 'https://my-frontend.com' or 'http://localhost:3000'
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

// Rate limiting: strong on login/refresh routes
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 min
  max: 20, // 20 attempts per 5 min per IP
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/auth/login', authLimiter);
app.use('/auth/refresh', authLimiter);

// Main routes
app.use('/auth', authRoutes);

export default app;
