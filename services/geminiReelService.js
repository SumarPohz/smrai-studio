import { GoogleGenAI } from '@google/genai';
import { generateScript as openaiGenerateScript } from './openaiService.js';

// ── Gemini client via @google/genai (same SDK used by Veo) ────────────────────
let _genai = null;
function getGCPProject() {
  if (process.env.GCP_PROJECT_ID) return process.env.GCP_PROJECT_ID;
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    try { return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON).project_id; } catch {}
  }
  return null;
}

function getGenAI() {
  if (_genai) return _genai;
  // Priority 1: Vertex AI Express — API key (simplest, no service account needed)
  const vertexApiKey = process.env.VERTEX_AI_API_KEY;
  if (vertexApiKey) {
    _genai = new GoogleGenAI({ vertexai: true, apiKey: vertexApiKey });
    return _genai;
  }
  // Priority 2: Vertex AI with service account (billing-enabled project)
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const project = getGCPProject();
    _genai = new GoogleGenAI({
      vertexai: true,
      project,
      location: 'us-central1',
      googleAuthOptions: {
        credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      },
    });
    return _genai;
  }
  // Priority 3: Free Gemini Developer API key
  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (apiKey) _genai = new GoogleGenAI({ apiKey });
  return _genai;
}

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
  realistic:  'photorealistic and cinematic — like a high-budget historical documentary film',
};

const WORD_TARGET = {
  '30-40': 'exactly 90 words — approximately 8 to 10 sentences',
  '60-70': 'exactly 175 words — approximately 18 to 22 sentences. This is a LONG script. Do NOT stop early. Write all sentences.',
};

// ── 60-minute long-form script generation ─────────────────────────────────────
// Generates ~9 000 words via 5 sequential chapter calls (~1 800 words each).

const CHAPTER_SYSTEM = `You are a professional audiobook and podcast scriptwriter.
Write engaging, spoken-word prose. No markdown, no bullet points, no headers.
Write only the text that will be read aloud. Every sentence must flow naturally into the next.`;

async function geminiText(prompt, maxTokens = 3500) {
  const response = await getGenAI().models.generateContent({
    model:    'gemini-2.5-flash',
    contents: prompt,
    config:   { temperature: 0.85, maxOutputTokens: maxTokens, thinkingConfig: { thinkingBudget: 0 } },
  });
  const text = response.text?.trim();
  if (!text) throw new Error('Empty response from Gemini');
  return text;
}

/**
 * Generate a ~60-minute spoken-word script (~9 000 words) via 5 Gemini calls.
 * Falls back to OpenAI single-call on any failure.
 * @param {string} topic
 * @returns {Promise<string>}
 */
export async function generateLongScript(topic) {
  if (!getGenAI()) {
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
  if (!getGenAI()) return chunks;

  const results = await Promise.all(chunks.map(async chunk => {
    const tone = TONE_MAP[artStyle] || TONE_MAP.cinematic;
    const prompt = `You are a world-class cinematographer writing a visual prompt for Google Veo 3 AI video generation.

Narration: "${chunk}"

Your task: describe EXACTLY what this narration is about as a visual scene.

CRITICAL RULES — follow strictly:
1. TIME PERIOD: Identify the era from the narration (ancient, medieval, biblical, modern, etc.) and SET the scene in that exact era. Do NOT modernize an ancient story.
2. CHARACTERS: Use the specific people/figures named (e.g. "Noah", "a Roman soldier", "a medieval king"). Do not replace them with generic modern people.
3. SETTING: Use the specific location described (e.g. "Mount Ararat", "an ancient wooden ark", "a desert oasis"). Do not replace with city streets or cafes.
4. STYLE APPLICATION: Apply "${tone}" ONLY to camera direction and lighting — not to the setting or characters. (e.g. "dramatic close-up", "golden hour", "slow aerial pan")
5. Keep it under 80 words. Dense, specific, photorealistic. Vertical 9:16 frame. No text, no subtitles.

Output only the visual scene description. Nothing else.`;
    try { return await geminiText(prompt, 200); }
    catch (e) { console.warn(`[GeminiReel] Visual rewrite failed: ${e.message} — using raw chunk`); return chunk; }
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
export async function generateScript(topic, { language = 'en', artStyle = 'cinematic', duration = '30-40', exScript = '', storyHint = '' } = {}) {
  const subject = storyHint && storyHint.trim().length > 0 ? storyHint.trim() : topic;
  if (!getGenAI()) {
    console.warn('[GeminiReel] Model not initialised — falling back to OpenAI');
    return openaiGenerateScript(subject, { language, artStyle, duration, exScript });
  }

  const lang       = LANG_MAP[language] || 'English';
  const tone       = TONE_MAP[artStyle]  || TONE_MAP.cinematic;
  const wordTarget = WORD_TARGET[duration] || WORD_TARGET['30-40'];

  const styleSection = exScript && exScript.trim().length > 10
    ? `\nStyle & tone reference — match this voice exactly:\n"""\n${exScript.trim()}\n"""\n`
    : '';

  const prompt = `You are a world-class documentary narrator telling gripping true stories for short-form video.
Write a "Based on a True Story" narrative about: "${subject}"

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
- IMPORTANT: Write the FULL target length. Do not stop until you reach the word count.
${styleSection}
Output only the narration sentences. Nothing else. Do not truncate.`;

  try {
    const result = await getGenAI().models.generateContent({
      model:    'gemini-2.5-flash',
      contents: prompt,
      config:   { temperature: 0.88, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 0 } },
    });

    const text = result.text?.trim();
    if (!text) throw new Error('Empty response from Gemini');
    return text;
  } catch (err) {
    console.error('[GeminiReel] generateContent failed:', err.message, '— falling back to OpenAI');
    return openaiGenerateScript(topic);
  }
}

/**
 * Generate reel metadata (title, hashtags, caption) via Gemini.
 * Falls back to empty strings on failure — caller should handle gracefully.
 */
export async function generateMetadata(script) {
  if (!getGenAI()) return { title: '', hashtags: [], caption: '' };

  try {
    const response = await getGenAI().models.generateContent({
      model:    'gemini-2.5-flash',
      contents: `You are a social media growth expert. Based on this reel script, generate:
- A viral title (max 10 words, curiosity-driven, no emojis)
- 5 trending, relevant hashtags (include the # symbol)
- 1 short caption (1 sentence, encourages engagement)

Script:
${script}

Respond ONLY with this exact JSON format (no extra text):
{"title":"","hashtags":["","","","",""],"caption":""}`,
      config: { temperature: 0.7, maxOutputTokens: 350 },
    });

    // Extract JSON object even if Gemini adds surrounding text or markdown fences
    const match  = (response.text || '').match(/\{[\s\S]*\}/);
    const parsed = JSON.parse(match ? match[0] : '{}');
    const result = {
      title:    parsed.title    || '',
      hashtags: Array.isArray(parsed.hashtags) ? parsed.hashtags : [],
      caption:  parsed.caption  || '',
    };
    console.log(`[Metadata] title="${result.title}" hashtags=${result.hashtags.length}`);
    return result;
  } catch (e) {
    console.warn('[Metadata] generateMetadata failed:', e.message);
    return { title: '', hashtags: [], caption: '' };
  }
}

/**
 * Generate a social media video description from the reel script.
 * 3–5 sentences, fact-rich, no hashtags (those are separate).
 */
export async function generateDescription(script) {
  if (!getGenAI()) return '';
  try {
    const response = await getGenAI().models.generateContent({
      model:    'gemini-2.5-flash',
      contents: `You are a social media content writer. Based on the reel script below, write a compelling video description for YouTube/Instagram/TikTok.

Rules:
- 3 to 5 sentences
- Summarise the key facts or story from the script in an engaging way
- Start with a hook sentence that makes people want to watch
- Do NOT include hashtags (those are added separately)
- Do NOT use phrases like "In this video" or "Watch as"
- Plain text only, no bullet points or markdown

Script:
${script}

Output only the description. Nothing else.`,
      config: { temperature: 0.75, maxOutputTokens: 250 },
    });
    const text = (response.text || '').trim();
    console.log(`[Metadata] description generated (${text.length} chars)`);
    return text;
  } catch (e) {
    console.warn('[Metadata] generateDescription failed:', e.message);
    return '';
  }
}
