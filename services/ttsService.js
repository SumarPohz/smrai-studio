import OpenAI from 'openai';
import { TextToSpeechClient } from '@google-cloud/text-to-speech';
import { SpeechClient } from '@google-cloud/speech';
import fs from 'fs/promises';
import path from 'path';
import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// ── OpenAI TTS client ──────────────────────────────────────────────────────────
let _openaiClient = null;
function getClient() {
  if (!_openaiClient) _openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _openaiClient;
}

// ── Shared service account resolver ───────────────────────────────────────────
function getServiceAccountJSON() {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_B64) {
    try { return JSON.parse(Buffer.from(process.env.GOOGLE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')); } catch {}
  }
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    try { return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON); } catch {}
  }
  return null;
}

// ── Google TTS client ──────────────────────────────────────────────────────────
// Uses GOOGLE_SERVICE_ACCOUNT_JSON (same creds as Gemini/Veo).
// Cloud Text-to-Speech API must be enabled in your GCP project.
let _googleTTSClient = null;
function getGoogleTTSClient() {
  if (_googleTTSClient) return _googleTTSClient;
  const sa = getServiceAccountJSON();
  if (sa) {
    _googleTTSClient = new TextToSpeechClient({ credentials: sa });
  } else {
    // Fall back to Application Default Credentials (local gcloud auth)
    _googleTTSClient = new TextToSpeechClient();
  }
  return _googleTTSClient;
}

// Maps OpenAI voice names → Google Neural2 voice names (en-US)
const GOOGLE_VOICE_MAP = {
  alloy:   'en-US-Neural2-F',  // neutral female
  echo:    'en-US-Neural2-D',  // male
  fable:   'en-US-Neural2-G',  // warm female
  onyx:    'en-US-Neural2-J',  // deep male
  nova:    'en-US-Neural2-E',  // female
  shimmer: 'en-US-Neural2-H',  // bright female
};

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
export async function generateTTS(script, voice, reelId, provider = 'openai', _retries = 2) {
  const safeVoice = AVAILABLE_VOICES.includes(voice) ? voice : 'alloy';
  const audioDir  = path.resolve('./public/audio');
  const audioPath = path.join(audioDir, `${reelId}.mp3`);

  await fs.mkdir(audioDir, { recursive: true });

  if (provider === 'google') {
    try {
      // 60s hard timeout — Google gRPC default is 300s which hangs the whole pipeline
      const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Google TTS timeout after 60s')), 60_000)
      );
      return await Promise.race([generateTTSViaGoogle(script, safeVoice, audioPath), timeout]);
    } catch (err) {
      console.warn(`[TTS] Google TTS failed (${err.message}) — falling back to OpenAI TTS`);
      // Fall through to OpenAI below
    }
  }

  try {
    const response = await getClient().audio.speech.create({
      model: 'tts-1',
      voice: safeVoice,
      input: script,
      speed: 1.0,
    });

    const buffer = Buffer.from(await response.arrayBuffer());
    await fs.writeFile(audioPath, buffer);
    return audioPath;
  } catch (err) {
    if (_retries > 0 && (err.message === 'terminated' || err.code === 'ECONNRESET')) {
      console.warn(`[TTS] Request terminated, retrying (${_retries} left)…`);
      await new Promise(r => setTimeout(r, 3000));
      return generateTTS(script, voice, reelId, provider, _retries - 1);
    }
    throw err;
  }
}

async function generateTTSViaGoogle(script, voice, outputPath) {
  const googleVoice = GOOGLE_VOICE_MAP[voice] || 'en-US-Neural2-F';
  console.log(`[TTS] Google Neural2 voice: ${googleVoice}`);

  const [response] = await getGoogleTTSClient().synthesizeSpeech({
    input:       { text: script },
    voice:       { languageCode: 'en-US', name: googleVoice },
    audioConfig: { audioEncoding: 'MP3', speakingRate: 1.0 },
  });

  await fs.writeFile(outputPath, response.audioContent, 'binary');
  return outputPath;
}

/**
 * Transcribe a TTS audio file with Whisper to get accurate word-level timestamps,
 * then group words into sentence segments at punctuation boundaries.
 * Returns null on any error — caller should fall back to WPM-based timing.
 *
 * @param {string} audioPath - absolute path to the TTS MP3
 * @returns {Promise<Array<{text:string, start:number, end:number}>|null>}
 */
export async function getWordTimestamps(audioPath) {
  try {
    const { createReadStream } = await import('fs');
    const resp = await getClient().audio.transcriptions.create({
      file:                    createReadStream(audioPath),
      model:                   'whisper-1',
      response_format:         'verbose_json',
      timestamp_granularities: ['word'],
    });

    if (!resp.words?.length) return null;

    const segments = [];
    let segStart = resp.words[0].start;
    let segWords = [];

    for (const w of resp.words) {
      segWords.push(w.word);
      if (/[.!?]['"]?$/.test(w.word.trim())) {
        segments.push({
          text:  segWords.join(' '),
          start: +segStart.toFixed(2),
          end:   +w.end.toFixed(2),
        });
        segStart = w.end;
        segWords = [];
      }
    }
    // Flush any trailing words not ending in punctuation
    if (segWords.length) {
      segments.push({
        text:  segWords.join(' '),
        start: +segStart.toFixed(2),
        end:   +resp.words.at(-1).end.toFixed(2),
      });
    }

    console.log(`[TTS] Whisper timestamps: ${segments.length} segments, ${resp.words.length} words`);
    return { segments, words: resp.words };
  } catch (err) {
    console.warn('[TTS] getWordTimestamps failed, falling back to WPM:', err.message);
    return null;
  }
}

// ── Google Cloud Speech-to-Text timestamps ────────────────────────────────────
let _sttClient = null;
function getSTTClient() {
  if (_sttClient) return _sttClient;
  const sa = getServiceAccountJSON();
  _sttClient = sa ? new SpeechClient({ credentials: sa }) : new SpeechClient();
  return _sttClient;
}

export async function getWordTimestampsViaGoogle(audioPath) {
  try {
    const audioBytes = await fs.readFile(audioPath);
    const [operation] = await getSTTClient().longRunningRecognize({
      audio:  { content: audioBytes.toString('base64') },
      config: {
        encoding:              'MP3',
        sampleRateHertz:       24000,
        languageCode:          'en-US',
        enableWordTimeOffsets: true,
        model:                 'latest_long',
      },
    });
    const [response] = await operation.promise();

    const words = response.results
      .flatMap(r => r.alternatives[0]?.words || [])
      .map(w => ({
        word:  w.word,
        start: +((+w.startTime.seconds || 0) + (w.startTime.nanos || 0) / 1e9).toFixed(2),
        end:   +((+w.endTime.seconds   || 0) + (w.endTime.nanos   || 0) / 1e9).toFixed(2),
      }));

    if (!words.length) return null;

    // Build sentence segments (same logic as Whisper path)
    const segments = [];
    let segStart = words[0].start;
    let segWords = [];
    for (const w of words) {
      segWords.push(w.word);
      if (/[.!?]['"]?$/.test(w.word.trim())) {
        segments.push({ text: segWords.join(' '), start: segStart, end: w.end });
        segStart = w.end;
        segWords = [];
      }
    }
    if (segWords.length) {
      segments.push({ text: segWords.join(' '), start: segStart, end: words.at(-1).end });
    }

    console.log(`[TTS] Google STT timestamps: ${words.length} words, ${segments.length} segments`);
    return { segments, words };
  } catch (err) {
    console.warn('[TTS] getWordTimestampsViaGoogle failed, falling back to WPM:', err.message);
    return null;
  }
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
  const safeVoice = AVAILABLE_VOICES.includes(voice) ? voice : 'alloy';
  const finalPath = path.resolve(`./public/audio/${fileId}.mp3`);
  const chunks    = splitIntoChunks(script);
  const partPaths = [];
  const useGoogle = !!getServiceAccountJSON();

  console.log(`[TTS] Generating ${chunks.length} chunks for ${fileId} (${script.split(/\s+/).length} words) via ${useGoogle ? 'Google Neural2' : 'OpenAI'}`);

  for (let i = 0; i < chunks.length; i++) {
    const partPath = path.resolve(`./public/audio/${fileId}-part${i}.mp3`);

    if (useGoogle) {
      try {
        const timeout = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Google TTS timeout')), 60_000)
        );
        await Promise.race([generateTTSViaGoogle(chunks[i], safeVoice, partPath), timeout]);
      } catch (err) {
        console.warn(`[TTS] Google chunk ${i} failed (${err.message}) — falling back to OpenAI`);
        const response = await getClient().audio.speech.create({
          model: 'tts-1', voice: safeVoice, input: chunks[i], speed: 1.0,
        });
        await fs.writeFile(partPath, Buffer.from(await response.arrayBuffer()));
      }
    } else {
      const response = await getClient().audio.speech.create({
        model: 'tts-1', voice: safeVoice, input: chunks[i], speed: 1.0,
      });
      await fs.writeFile(partPath, Buffer.from(await response.arrayBuffer()));
    }

    partPaths.push(partPath);
  }

  if (partPaths.length === 1) {
    await fs.rename(partPaths[0], finalPath);
  } else {
    await concatMp3s(partPaths, finalPath);
    await Promise.all(partPaths.map(p => fs.unlink(p).catch(() => {})));
  }

  console.log(`[TTS] Long audio complete → ${finalPath}`);
  return finalPath;
}
