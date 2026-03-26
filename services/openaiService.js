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

/**
 * STEP 1 — Generate a viral, line-by-line reel script (~45–60 seconds)
 * Each output line becomes a subtitle in the final video.
 *
 * @param {string} topic
 * @returns {Promise<string>} script text
 */
export async function generateScript(topic) {
  const res = await getClient().chat.completions.create({
    model: SCRIPT_MODEL,
    messages: [
      {
        role: 'system',
        content:
          'You are a viral short-form video scriptwriter. ' +
          'Write scripts line-by-line where each line becomes a subtitle. ' +
          'No emojis, no hashtags, no stage directions. Plain spoken text only.',
      },
      {
        role: 'user',
        content:
          `Topic: "${topic}"\n\n` +
          'Write a 45–60 second faceless reel script.\n' +
          'Structure:\n' +
          '1. Hook — one powerful attention-grabbing opening line\n' +
          '2. Build curiosity — 2-3 lines\n' +
          '3. Main content — fast-paced, short punchy lines\n' +
          '4. Twist or insight — one surprising line\n' +
          '5. Ending — one memorable closing line\n\n' +
          'Tone: emotional, engaging, slightly dramatic.\n' +
          'Output: plain text, one line per subtitle, no labels or emojis.',
      },
    ],
    max_tokens: 350,
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
