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

// ── 60-minute long-form script generation ─────────────────────────────────────
// Generates ~9 000 words via 5 sequential chapter calls (~1 800 words each).

const CHAPTER_SYSTEM = `You are a professional audiobook and podcast scriptwriter.
Write engaging, spoken-word prose. No markdown, no bullet points, no headers.
Write only the text that will be read aloud. Every sentence must flow naturally into the next.`;

async function geminiText(prompt, maxTokens = 3500) {
  const result = await geminiModel.generateContent({
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.85, maxOutputTokens: maxTokens },
  });
  return result.response?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
}

/**
 * Generate a ~60-minute spoken-word script (~9 000 words) via 5 Gemini calls.
 * Falls back to OpenAI single-call on any failure.
 * @param {string} topic
 * @returns {Promise<string>}
 */
export async function generateLongScript(topic) {
  if (!geminiModel) {
    console.warn('[GeminiReel] Model not initialised — falling back to OpenAI');
    return openaiGenerateScript(topic);
  }

  try {
    // 1. Build a 5-chapter outline
    const outlinePrompt = `${CHAPTER_SYSTEM}

Topic: "${topic}"

Create a detailed 5-chapter outline for a 60-minute audio story/documentary.
For each chapter write:
  - Chapter number and title (one line)
  - A 2–3 sentence description of what happens in that chapter

Keep descriptions vivid and specific. This outline will guide full chapter writing next.`;

    const outline = await geminiText(outlinePrompt, 700);
    console.log('[GeminiReel] Outline generated for:', topic);

    // 2. Extract chapter titles from outline (lines starting with "Chapter")
    const chapterLines = outline
      .split('\n')
      .filter(l => /^chapter\s+\d+/i.test(l.trim()))
      .map(l => l.trim());

    const parts = [];
    for (let i = 0; i < 5; i++) {
      const chapterTitle = chapterLines[i] || `Chapter ${i + 1}`;
      const isFirst = i === 0;
      const isLast  = i === 4;

      const chapterPrompt = `${CHAPTER_SYSTEM}

You are writing ${chapterTitle} of a 60-minute audio story about: "${topic}"

Full outline for context:
${outline}

Instructions:
- Write approximately 1 800 words for this chapter
- ${isFirst ? 'Open with a powerful hook — the very first sentence must grab the listener.' : `Transition smoothly from the previous chapter.`}
- Write in flowing spoken prose — natural rhythm, vivid imagery, emotional pull
- ${isLast ? 'End with a powerful, memorable closing that leaves the listener satisfied.' : 'Close with a sentence that creates anticipation for the next chapter.'}
- NO chapter headings, NO markdown, NO meta-commentary — just the narration text`;

      const chapterText = await geminiText(chapterPrompt, 3000);
      parts.push(chapterText);
    }

    const fullScript = parts.join('\n\n');
    console.log(`[GeminiReel] Long script complete: ~${fullScript.split(/\s+/).length} words`);
    return fullScript;
  } catch (err) {
    console.error('[GeminiReel] generateLongScript failed:', err.message, '— falling back to OpenAI');
    return openaiGenerateScript(topic);
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Generate a viral faceless reel script using Gemini 2.0 Flash.
 * Falls back to OpenAI if Gemini is unavailable.
 *
 * @param {string} topic
 * @param {{ language?: string, artStyle?: string, duration?: string, exScript?: string }} opts
 * @returns {Promise<string>}
 */
export async function generateScript(topic, { language = 'en', artStyle = 'cinematic', duration = '30-40', exScript = '' } = {}) {
  if (!geminiModel) {
    console.warn('[GeminiReel] Model not initialised — falling back to OpenAI');
    return openaiGenerateScript(topic);
  }

  const lang       = LANG_MAP[language] || 'English';
  const tone       = TONE_MAP[artStyle]  || TONE_MAP.cinematic;
  const wordTarget = WORD_TARGET[duration] || WORD_TARGET['30-40'];

  const styleSection = exScript && exScript.trim().length > 10
    ? `\nStyle & tone reference — match this voice exactly:\n"""\n${exScript.trim()}\n"""\n`
    : '';

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
${styleSection}
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
