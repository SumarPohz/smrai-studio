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
  realistic:  'grounded, journalistic, and matter-of-fact — like a true-crime documentary',
};

const WORD_TARGET = {
  '30-40': '80 to 100 words',
  '60-70': '160 to 185 words',
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
    return openaiGenerateScript(topic, { duration: '60-70' });
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
    return openaiGenerateScript(topic, { duration: '60-70' });
  }
}

// ── Visual scene rewriting ────────────────────────────────────────────────────

/**
 * Convert narration script chunks into cinematic visual scene descriptions
 * suitable as prompts for AI video generation.
 * All chunks are processed in parallel. Falls back to original chunk on any error.
 *
 * @param {string[]} chunks   - raw narration text chunks
 * @param {string}   artStyle - e.g. 'cinematic', 'creepy'
 * @returns {Promise<string[]>} visual scene descriptions (same length as chunks)
 */
export async function rewriteChunksAsVisualScenes(chunks, artStyle = 'cinematic') {
  if (!geminiModel) return chunks;

  const results = await Promise.all(chunks.map(async chunk => {
    const tone = TONE_MAP[artStyle] || TONE_MAP.cinematic;
    const prompt = `You are a cinematographer writing visual prompts for an AI video generator.
Convert this narration into a vivid visual scene description for a ${tone} style video.

Narration: "${chunk}"

Rules:
- Describe what the CAMERA SEES — lighting, colors, movement, atmosphere, subjects
- Under 100 words
- Vertical 9:16 portrait composition
- No text overlays, no subtitles, no dialogue

Output only the visual scene description.`;
    try { return await geminiText(prompt, 180); }
    catch { return chunk; }
  }));

  console.log(`[GeminiReel] Rewrote ${chunks.length} script chunks as visual scenes`);
  return results;
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
    return openaiGenerateScript(topic, { language, artStyle, duration, exScript });
  }

  const lang       = LANG_MAP[language] || 'English';
  const tone       = TONE_MAP[artStyle]  || TONE_MAP.cinematic;
  const wordTarget = WORD_TARGET[duration] || WORD_TARGET['30-40'];

  const styleSection = exScript && exScript.trim().length > 10
    ? `\nStyle & tone reference — match this voice exactly:\n"""\n${exScript.trim()}\n"""\n`
    : '';

  const prompt = `You are a world-class documentary narrator telling gripping true stories for short-form video.
Write a "Based on a True Story" narrative about: "${topic}"

Requirements:
- Language: ${lang}
- Tone: ${tone}
- Length: ${wordTarget}
- Format: one sentence per line — flowing story narrative, not bullet points
- Open with a jaw-dropping real fact or event that immediately hooks the viewer
- Build tension through the middle — reveal surprising details, real names, real places, real consequences
- Write as if narrating a documentary — authoritative, vivid, and emotionally gripping
- Close with a fact or twist that makes the viewer reflect or share
- NO emojis, hashtags, stage directions, or speaker labels
- NO phrases like "Based on a true story" — just tell it as the narrator
${styleSection}
Output only the narration sentences. Nothing else.`;

  try {
    const result = await geminiModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.88, maxOutputTokens: 600 },
    });

    const text = result.response?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!text) throw new Error('Empty response from Gemini');
    return text;
  } catch (err) {
    console.error('[GeminiReel] generateContent failed:', err.message, '— falling back to OpenAI');
    return openaiGenerateScript(topic);
  }
}
