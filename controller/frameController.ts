import { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { sendFrameToVPS } from '../services/vpsDetectionService';
import { generateAudio } from '../services/textToSpeechService';

const unlinkAsync = promisify(fs.unlink);

export const processFrame = async (
  req: Request,
  res: Response
): Promise<void> => {
  const framePath = req.file?.path;

  try {
    // Validate file presence
    if (!framePath) {
      console.error(`[${new Date().toISOString()}] No frame file provided`);
      res.status(400).json({ error: { code: 'NO_FILE', message: 'No frame file provided' } });
      return;
    }

    console.log(`[${new Date().toISOString()}] Processing frame: ${framePath}`);

    // Process the frame
    const detections = await sendFrameToVPS(framePath);

    // Check for VPS errors
    if (detections.includes('Error detecting') || detections.includes('Frame extraction failed')) {
      console.error(`[${new Date().toISOString()}] VPS processing failed: ${detections}`);
      res.status(500).json({ error: { code: 'VPS_FAILED', message: 'Failed to process frame on VPS' } });
      return;
    }

    // Generate audio if there are detections
    let audioUrl: string | null = null;
    if (detections.length > 0) {
      audioUrl = await generateAudio(detections);
      if (!audioUrl || typeof audioUrl !== 'string' || !audioUrl.startsWith('https://')) {
        console.error(`[${new Date().toISOString()}] Audio generation failed: ${audioUrl}`);
        res.status(500).json({ error: { code: 'AUDIO_FAILED', message: 'Failed to generate audio' } });
        return;
      }
    }

    // Send successful response
    console.log(`[${new Date().toISOString()}] Frame processed successfully:`, { commands: detections, audioUrl });
    res.json({ data: { commands: detections, audioUrl } });
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] Error processing frame:`, {
      message: error.message,
      stack: error.stack,
      framePath,
    });
    res.status(500).json({ error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  } finally {
    // Clean up files
    try {
      if (framePath && fs.existsSync(framePath)) {
        await unlinkAsync(framePath);
        console.log(`[${new Date().toISOString()}] Cleaned up frame file: ${framePath}`);
      }
    } catch (cleanupError: any) {
      console.error(`[${new Date().toISOString()}] File cleanup failed: ${cleanupError.message}`);
    }
  }
};