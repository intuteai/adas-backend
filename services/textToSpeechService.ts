const googleTTS = require('google-tts-api');

export const generateAudio = async (commands: string[]): Promise<string> => {
  try {
    // Validate input
    if (!Array.isArray(commands) || commands.length === 0) {
      console.error('Invalid input: commands must be a non-empty array');
      throw new Error('Invalid input: commands must be a non-empty array');
    }

    // Ensure all elements are strings
    const validCommands = commands.filter((cmd) => typeof cmd === 'string' && cmd.trim() !== '');
    if (validCommands.length === 0) {
      console.error('Invalid input: no valid commands to process');
      throw new Error('Invalid input: no valid commands to process');
    }

    const sentence = validCommands.join('. ');
    console.log('Generating audio for sentence:', sentence);

    const audioUrl = await googleTTS.getAudioUrl(sentence, {
      lang: 'en',
      slow: false,
      host: 'https://translate.google.com',
    });

    // Validate audio URL
    if (!audioUrl || typeof audioUrl !== 'string' || !audioUrl.startsWith('https://')) {
      console.error('Invalid audio URL generated:', audioUrl);
      throw new Error('Failed to generate a valid audio URL');
    }

    console.log('Audio URL generated successfully:', audioUrl);
    return audioUrl;
  } catch (error: any) {
    console.error('Error generating audio:', error.message, error.stack);
    throw new Error('Audio generation failed: ' + error.message);
  }
};