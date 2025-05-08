import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { getAuth } from 'firebase-admin/auth';
import admin from 'firebase-admin';
import frameRoutes from './routes/frameRoutes';

dotenv.config();

// Initialize Firebase Admin from env instead of file
try {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Firebase Admin initialization failed:', error);
  process.exit(1);
}

const app = express();

// Enhanced logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`[${new Date().toISOString()}] Incoming request: ${req.method} ${req.url} from ${req.headers.origin || 'no-origin'} | IP: ${req.ip}`);
  next();
});

app.use(cors({ origin: '*', optionsSuccessStatus: 200 }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests, please try again later.' } },
});
app.use('/process_frame', limiter);

// Firebase Authentication Middleware
const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  console.log('Authentication middleware triggered for:', req.url);
  const token = req.headers.authorization?.split('Bearer ')[1];
  console.log('Token received:', token ? 'present' : 'absent');
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'No token provided' } });
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

// Routes
app.use('/process_frame', frameRoutes);

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(`[${new Date().toISOString()}] Unhandled error:`, err.message, err.stack);
  res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message || 'Internal server error' } });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend server running on port ${PORT}`);
});
