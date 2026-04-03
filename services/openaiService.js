import OpenAI from 'openai';

// Model constants — never mix these
const SCRIPT_MODEL = 'gpt-4.1-mini';   // Step 1: high-quality script generation
const META_MODEL   = 'gpt-4.1-nano';   // Step 2: cheap metadata (title/tags/caption)

// Lazy init — dotenv hasn't run yet at import time in ES Modules
let _client = null;
function getClient() {
  if (!_client) _client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _client;
}

const LANG_MAP = {
  en: 'English', hi: 'Hindi', es: 'Spanish', fr: 'French',
  de: 'German', pt: 'Portuguese', ja: 'Japanese', ko: 'Korean',
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
  '30-40': { words: '80 to 100 words', tokens: 180 },
  '60-70': { words: '160 to 185 words', tokens: 320 },
};

/**
 * STEP 1 — Generate a "Based on a True Story" documentary-narrator reel script.
 * Supports short (30-40s) and long (60-70s) durations.
 *
 * @param {string} topic
 * @param {{ language?: string, artStyle?: string, duration?: string, exScript?: string }} opts
 * @returns {Promise<string>} script text
 */
export async function generateScript(topic, { language = 'en', artStyle = 'cinematic', duration = '30-40', exScript = '' } = {}) {
  const lang       = LANG_MAP[language] || 'English';
  const tone       = TONE_MAP[artStyle]  || TONE_MAP.cinematic;
  const target     = WORD_TARGET[duration] || WORD_TARGET['30-40'];

  const styleSection = exScript && exScript.trim().length > 10
    ? `\nStyle & tone reference — match this voice exactly:\n"""\n${exScript.trim()}\n"""`
    : '';

  const res = await getClient().chat.completions.create({
    model: SCRIPT_MODEL,
    messages: [
      {
        role: 'system',
        content: 'You are a world-class documentary narrator telling gripping true stories for short-form video. Write engaging spoken-word prose. No emojis, no hashtags, no stage directions, no speaker labels.',
      },
      {
        role: 'user',
        content:
          `Write a "Based on a True Story" narrative about: "${topic}"\n\n` +
          `Language: ${lang}\n` +
          `Tone: ${tone}\n` +
          `Length: ${target.words}\n` +
          `Format: one sentence per line — flowing story narrative, not bullet points\n` +
          `- Open with a jaw-dropping real fact or event that immediately hooks the viewer\n` +
          `- Build tension through the middle — reveal surprising details, real names, real places, real consequences\n` +
          `- Write as if narrating a documentary — authoritative, vivid, and emotionally gripping\n` +
          `- Close with a fact or twist that makes the viewer reflect or share\n` +
          `- NO phrases like "Based on a true story" — just tell it as the narrator\n` +
          `${styleSection}\n` +
          `Output only the narration sentences. Nothing else.`,
      },
    ],
    max_tokens: target.tokens,
    temperature: 0.85,
  });

  return res.choices[0].message.content.trim();
}

/**
 * STEP 2 — Generate viral metadata from the script (title, hashtags, caption).
 * Uses the cheapest model since this is simple JSON extraction.
 *
 * @param {string} script - the generated script from Step 1
 * @returns {Promise<{title: string, hashtags: string[], caption: string}>}
 */
export async function generateMetadata(script) {
  const res = await getClient().chat.completions.create({
    model: META_MODEL,
    messages: [
      {
        role: 'system',
        content: 'You are a social media growth expert. Always respond with valid JSON only.',
      },
      {
        role: 'user',
        content:
          'Based on this reel script, generate:\n' +
          '- A viral title (max 10 words, curiosity-driven, no emojis)\n' +
          '- 5 trending, relevant hashtags (include the # symbol)\n' +
          '- 1 short caption (1 sentence, encourages engagement)\n\n' +
          `Script:\n${script}\n\n` +
          'Respond ONLY with this exact JSON format:\n' +
          '{"title":"","hashtags":["","","","",""],"caption":""}',
      },
    ],
    max_tokens: 150,
    temperature: 0.7,
    response_format: { type: 'json_object' },
  });

  try {
    const parsed = JSON.parse(res.choices[0].message.content);
    return {
      title:    parsed.title    || '',
      hashtags: Array.isArray(parsed.hashtags) ? parsed.hashtags : [],
      caption:  parsed.caption  || '',
    };
  } catch {
    return { title: '', hashtags: [], caption: '' };
  }
}
