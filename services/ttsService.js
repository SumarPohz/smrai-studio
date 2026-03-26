import OpenAI from 'openai';
import fs from 'fs/promises';
import path from 'path';

// Lazy init — dotenv hasn't run yet at import time in ES Modules
let _client = null;
function getClient() {
  if (!_client) _client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _client;
}

export const AVAILABLE_VOICES = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];

/**
 * Convert script text to MP3 using OpenAI TTS
 * @param {string} script - Text to convert
 * @param {string} voice  - One of: alloy, echo, fable, onyx, nova, shimmer
 * @param {number} reelId - Used to name the output file
 * @returns {Promise<string>} absolute path to saved MP3
 */
export async function generateTTS(script, voice, reelId) {
  const safeVoice = AVAILABLE_VOICES.includes(voice) ? voice : 'alloy';
  const audioPath = path.resolve(`./public/audio/${reelId}.mp3`);

  const response = await getClient().audio.speech.create({
    model: 'tts-1',
    voice: safeVoice,
    input: script,
    speed: 1.0,
  });

  const buffer = Buffer.from(await response.arrayBuffer());
  await fs.writeFile(audioPath, buffer);

  return audioPath;
}
