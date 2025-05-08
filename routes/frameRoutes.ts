import express from 'express';
import multer from 'multer';
import path from 'path';
import { processFrame } from '../controller/frameController';

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const originalName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '-'); // Sanitize filename
    cb(null, `${timestamp}-${originalName}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg']; // Updated to accept only JPEG images
    if (!allowedTypes.includes(file.mimetype)) {
      console.log(`Invalid file type: ${file.mimetype}`);
      return cb(new Error('Only JPEG images are allowed'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for images (adjust as needed)
});

// Error-handling middleware for multer
const handleMulterError = (
  err: any,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void => {
  if (err instanceof multer.MulterError) {
    console.error(`Multer error: ${err.message} | Field: ${err.field}`);
    res.status(400).json({ error: { code: 'UPLOAD_FAILED', message: err.message } });
    return;
  } else if (err) {
    console.error(`Upload error: ${err.message}`);
    res.status(400).json({ error: { code: 'INVALID_FILE', message: err.message } });
    return;
  }
  next();
};

// Route with regular middleware
router.post('/', upload.single('frame'), processFrame); // Updated field name to 'frame'

// Apply error-handling middleware separately
router.use(handleMulterError);

export default router;