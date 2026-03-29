import { VertexAI } from '@google-cloud/vertexai';
import { generateScript as openaiGenerateScript } from './openaiService.js';

// ── Gemini model initialisation (mirrors app.js pattern) ──────────────────────
let geminiModel = null;
try {
  const opts = {
    project:  process.env.GCP_PROJECT_ID,
    location: 'us-central1',
  };

  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    opts.googleAuthOptions = {
      credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    };
  }

  const vertexAI = new VertexAI(opts);
  geminiModel = vertexAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
} catch (_) {}

// ── Maps ──────────────────────────────────────────────────────────────────────

const LANG_MAP = {
  en: 'English',
  hi: 'Hindi',
  es: 'Spanish',
  fr: 'French',
  de: 'German',
  pt: 'Portuguese',
  ja: 'Japanese',
  ko: 'Korean',
};

const TONE_MAP = {
  cinematic:  'dramatic and suspenseful, like a movie trailer narration',
  creepy:     'dark, eerie, and unsettling — builds dread',
  vibrant:    'energetic, upbeat, and punchy',
  disney:     'whimsical, warm, and family-friendly',
  nature:     'peaceful, awe-inspiring, and grounded',
  urban:      'gritty, fast-paced, and modern',
  fantasy:    'mystical, epic, and wonder-filled',
  historical: 'authoritative, educational, and vivid',
};

const WORD_TARGET = {
  '30-40': '75 to 100 words',
  '60-70': '150 to 175 words',
};

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Generate a viral faceless reel script using Gemini 2.0 Flash.
 * Falls back to OpenAI if Gemini is unavailable.
 *
 * @param {string} topic
 * @param {{ language?: string, artStyle?: string, duration?: string }} opts
 * @returns {Promise<string>}
 */
export async function generateScript(topic, { language = 'en', artStyle = 'cinematic', duration = '30-40' } = {}) {
  if (!geminiModel) {
    console.warn('[GeminiReel] Model not initialised — falling back to OpenAI');
    return openaiGenerateScript(topic);
  }

  const lang       = LANG_MAP[language] || 'English';
  const tone       = TONE_MAP[artStyle]  || TONE_MAP.cinematic;
  const wordTarget = WORD_TARGET[duration] || WORD_TARGET['30-40'];

  const prompt = `You are a viral faceless short-form video scriptwriter.
Write a script about: "${topic}"

Requirements:
- Language: ${lang}
- Tone: ${tone}
- Length: ${wordTarget}
- Format: short punchy lines, one sentence per line (subtitle-ready)
- NO emojis, hashtags, stage directions, or speaker labels
- First line must be a powerful hook that stops the scroll
- Last line must be a memorable, shareable closing

Output only the script lines. Nothing else.`;

  try {
    const result = await geminiModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.88, maxOutputTokens: 450 },
    });

    const text = result.response?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!text) throw new Error('Empty response from Gemini');
    return text;
  } catch (err) {
    console.error('[GeminiReel] generateContent failed:', err.message, '— falling back to OpenAI');
    return openaiGenerateScript(topic);
  }
}
