import OpenAI from 'openai';
import fs from 'fs/promises';
import path from 'path';
import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// Lazy init — dotenv hasn't run yet at import time in ES Modules
let _client = null;
function getClient() {
  if (!_client) _client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _client;
}

export const AVAILABLE_VOICES = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];

const PREVIEW_TEXT = "Hey there! I'm your AI narrator, ready to bring your stories to life.";

/**
 * Generate a short voice preview clip and cache it as preview-{voice}.mp3.
 * Returns the absolute path to the cached MP3.
 * @param {string} voice
 * @returns {Promise<string>} absolute file path
 */
export async function generateVoicePreview(voice) {
  const safeVoice = AVAILABLE_VOICES.includes(voice) ? voice : 'alloy';
  const previewPath = path.resolve(`./public/audio/preview-${safeVoice}.mp3`);

  // Serve cached file if it already exists
  try {
    await fs.access(previewPath);
    return previewPath;
  } catch {}

  // Generate and cache
  const response = await getClient().audio.speech.create({
    model: 'tts-1',
    voice: safeVoice,
    input: PREVIEW_TEXT,
    speed: 1.0,
  });

  const buffer = Buffer.from(await response.arrayBuffer());
  await fs.writeFile(previewPath, buffer);
  return previewPath;
}

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

// ── Long-form TTS (60-min scripts) ────────────────────────────────────────────

const MAX_TTS_CHARS = 3800; // OpenAI tts-1 hard limit is 4 096; stay safely below

/**
 * Split a long script into chunks at sentence boundaries.
 * Never splits mid-sentence; each chunk is ≤ maxChars characters.
 */
function splitIntoChunks(text, maxChars = MAX_TTS_CHARS) {
  const chunks = [];
  // Split on sentence-ending punctuation followed by whitespace or end-of-string
  const sentences = text.match(/[^.!?]+[.!?]+[\s]*/g) || [text];
  let current = '';

  for (const sentence of sentences) {
    if ((current + sentence).length > maxChars && current.length > 0) {
      chunks.push(current.trimEnd());
      current = sentence;
    } else {
      current += sentence;
    }
  }
  if (current.trim()) chunks.push(current.trim());
  return chunks.filter(c => c.length > 0);
}

/** Concatenate multiple MP3 files into one using FFmpeg concat demuxer. */
function concatMp3s(inputPaths, outputPath) {
  return new Promise(async (resolve, reject) => {
    const listPath = outputPath + '.txt';
    // FFmpeg concat demuxer requires escaped absolute paths
    const listContent = inputPaths
      .map(p => `file '${p.replace(/\\/g, '/').replace(/'/g, "'\\''")}'`)
      .join('\n');
    await fs.writeFile(listPath, listContent);

    ffmpeg()
      .input(listPath)
      .inputOptions(['-f', 'concat', '-safe', '0'])
      .outputOptions(['-c', 'copy'])
      .output(outputPath)
      .on('end', () => { fs.unlink(listPath).catch(() => {}); resolve(outputPath); })
      .on('error', (err) => { fs.unlink(listPath).catch(() => {}); reject(err); })
      .run();
  });
}

/**
 * Convert a long script (~9 000 words) to a single MP3 by:
 *   1. Splitting into ≤3 800-char sentence-boundary chunks
 *   2. Calling tts-1 for each chunk in sequence
 *   3. Concatenating all part files into one final MP3 via FFmpeg
 *
 * @param {string} script   - Full spoken-word script
 * @param {string} voice    - One of AVAILABLE_VOICES
 * @param {string} fileId   - Base filename (e.g. "tts-42") → public/audio/tts-42.mp3
 * @returns {Promise<string>} absolute path to final MP3
 */
export async function generateLongTTS(script, voice, fileId) {
  const safeVoice  = AVAILABLE_VOICES.includes(voice) ? voice : 'alloy';
  const finalPath  = path.resolve(`./public/audio/${fileId}.mp3`);
  const chunks     = splitIntoChunks(script);
  const partPaths  = [];

  console.log(`[TTS] Generating ${chunks.length} chunks for ${fileId} (${script.split(/\s+/).length} words)`);

  for (let i = 0; i < chunks.length; i++) {
    const partPath = path.resolve(`./public/audio/${fileId}-part${i}.mp3`);
    const response = await getClient().audio.speech.create({
      model: 'tts-1',
      voice: safeVoice,
      input: chunks[i],
      speed: 1.0,
    });
    const buffer = Buffer.from(await response.arrayBuffer());
    await fs.writeFile(partPath, buffer);
    partPaths.push(partPath);
  }

  if (partPaths.length === 1) {
    // Single chunk — just move it to the final path
    await fs.rename(partPaths[0], finalPath);
  } else {
    await concatMp3s(partPaths, finalPath);
    // Clean up part files
    await Promise.all(partPaths.map(p => fs.unlink(p).catch(() => {})));
  }

  console.log(`[TTS] Long audio complete → ${finalPath}`);
  return finalPath;
}
