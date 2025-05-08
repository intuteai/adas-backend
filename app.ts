import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { getAuth } from 'firebase-admin/auth';
import admin from 'firebase-admin';
import frameRoutes from './routes/frameRoutes';

// Load environment variables
dotenv.config();

// Initialize Firebase Admin (requires service account key)
try {
  admin.initializeApp({
    credential: admin.credential.cert(process.env.FIREBASE_SERVICE_ACCOUNT_PATH || ''),
  });
  console.log('Firebase Admin initialized successfully');
} catch (error) {
  console.error('Firebase Admin initialization failed:', error);
  process.exit(1);
}

const app = express();

// Enhanced logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`[${new Date().toISOString()}] Incoming request: ${req.method} ${req.url} from ${req.headers.origin || 'no-origin'} | IP: ${req.ip}`);
  next();
});

// Temporary CORS to allow all origins for debugging
app.use(cors({
  origin: '*', // Allow all origins temporarily
  optionsSuccessStatus: 200,
}));

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests, please try again later.' } },
});
app.use('/process_frame', limiter);

// Firebase Authentication Middleware with debug
const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  console.log('Authentication middleware triggered for:', req.url);
  const token = req.headers.authorization?.split('Bearer ')[1];
  console.log('Token received:', token ? 'present' : 'absent');
  if (!token) {
    console.log('No token provided');
    res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'No token provided' } });
    return;
  }
  try {
    const decodedToken = await getAuth().verifyIdToken(token);
    console.log('Token verified successfully for user:', decodedToken.uid);
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(401).json({ error: { code: 'INVALID_TOKEN', message: 'Invalid token' } });
  }
};
app.use('/process_frame', authenticate);

// Mount routes
app.use('/process_frame', frameRoutes);

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(`[${new Date().toISOString()}] Unhandled error:`, err.message, err.stack);
  res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message || 'Internal server error' } });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend server running at http://localhost:${PORT}`);
});