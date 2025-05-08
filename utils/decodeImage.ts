import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export default async function decodeImage(base64Image: string): Promise<string> {
  try {
    // Validate base64 string
    const matches = base64Image.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
    if (!matches) {
      console.error('Invalid base64 string provided');
      throw new Error('Invalid base64 string');
    }

    // Ensure uploads directory exists
    const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, '../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
      console.log('Created uploads directory:', uploadDir);
    }

    // Decode and save image
    const buffer = Buffer.from(matches[2], 'base64');
    const filePath = path.join(uploadDir, `${Date.now()}.jpg`);
    fs.writeFileSync(filePath, buffer);
    console.log('Image decoded and saved:', filePath);

    return filePath;
  } catch (error: any) {
    console.error('Error decoding image:', error.message, error.stack);
    throw new Error('Failed to decode image: ' + error.message);
  }
}