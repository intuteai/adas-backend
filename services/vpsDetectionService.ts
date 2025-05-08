import axios from 'axios';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export const sendFrameToVPS = async (framePath: string): Promise<string[]> => {
  const VPS_URL = process.env.VPS_URL || 'http://148.66.155.196:5050';

  try {
    if (!fs.existsSync(framePath)) {
      console.error('Frame file not found:', framePath);
      return ['Frame file not found'];
    }

    const base64Image = fs.readFileSync(framePath, { encoding: 'base64' });

    const response = await axios.post(VPS_URL, {
      image: `data:image/jpeg;base64,${base64Image}`,
    });

    // Check if response data exists
    if (!response.data) {
      console.error('Invalid VPS response: No data received');
      return ['Invalid response from VPS'];
    }

    // Extract available parameters
    const { eye_closed, head_direction, microsleep, yawn, danger_level, fatigue_score, phone_detected } = response.data;

    // Construct commands array based on available VPS data
    const commands: string[] = [];

    // Process each parameter independently if it exists
    if (eye_closed !== undefined) {
      const eyeState = eye_closed ? 'closed' : 'open';
      commands.push(`Eyes ${eyeState}`);
    }
    if (head_direction !== undefined) {
      commands.push(`Head direction: ${head_direction.toLowerCase()}`);
    }
    if (microsleep !== undefined && microsleep) {
      commands.push('Microsleep detected');
    }
    if (yawn !== undefined && yawn) {
      commands.push('stay alert');
    }
    if (danger_level !== undefined) {
      commands.push(`Danger level: ${danger_level}`);
    }
    if (fatigue_score !== undefined) {
      commands.push(`Fatigue score: ${fatigue_score}`);
    }
    if (phone_detected !== undefined && phone_detected) {
      commands.push('Phone detected');
    }

    console.log('VPS detection successful:', commands);
    return commands;
  } catch (error: any) {
    console.error('❌ Error sending frame to VPS:', error.message, error.stack);
    return ['Error detecting'];
  }
};