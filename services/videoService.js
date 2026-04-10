import fetch from 'node-fetch';
import fsp from 'fs/promises';
import fs from 'fs';
import https from 'https';
import http from 'http';
import path from 'path';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import { execFile } from 'child_process';
import { promisify } from 'util';
import OpenAI from 'openai';
import { GoogleGenAI } from '@google/genai';
import { rewriteChunksAsVisualScenes } from './geminiReelService.js';

// ── Google Veo client (lazy) ──────────────────────────────────────────────────

// Resolves service account JSON from either raw JSON or Base64-encoded env var
function getServiceAccountJSON() {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_B64) {
    try { return JSON.parse(Buffer.from(process.env.GOOGLE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')); } catch {}
  }
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    try { return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON); } catch {}
  }
  return null;
}

function getGCPProject() {
  if (process.env.GCP_PROJECT_ID) return process.env.GCP_PROJECT_ID;
  return getServiceAccountJSON()?.project_id || null;
}

let _veoClient = null;
function getVeoClient() {
  if (_veoClient) return _veoClient;
  const location = process.env.GCP_LOCATION || 'us-central1';
  // Priority 1: Vertex AI Express — API key
  const vertexApiKey = process.env.VERTEX_AI_API_KEY;
  if (vertexApiKey) {
    _veoClient = new GoogleGenAI({ vertexai: true, apiKey: vertexApiKey });
    return _veoClient;
  }
  // Priority 2: Service account
  const sa = getServiceAccountJSON();
  if (sa) {
    try {
      _veoClient = new GoogleGenAI({
        vertexai: true,
        project:  sa.project_id,
        location,
        googleAuthOptions: {
          credentials: sa,
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      });
      return _veoClient;
    } catch (e) {
      console.error('[VideoGen] Failed to init Veo with service account:', e.message);
    }
  }
  // Priority 3: Generic Google API key
  if (process.env.GOOGLE_API_KEY) {
    const project = getGCPProject();
    _veoClient = new GoogleGenAI({ vertexai: true, project, location, apiKey: process.env.GOOGLE_API_KEY });
  }
  return _veoClient;
}

const execFileAsync = promisify(execFile);

let _openai = null;
function getOpenAI() {
  if (!_openai) _openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _openai;
}

const XAI_BASE  = 'https://api.x.ai/v1';
// Generate a solid-black test clip of given duration using FFmpeg's built-in lavfi source
async function makeMockClip(dest, durationSec) {
  await execFileAsync(ffmpegInstaller.path, [
    '-y',
    '-f', 'lavfi', '-i', `color=c=black:size=720x1280:rate=24:duration=${durationSec}`,
    '-f', 'lavfi', '-i', 'anullsrc=r=44100:cl=stereo',
    '-t', String(durationSec),
    '-c:v', 'libx264', '-pix_fmt', 'yuv420p',
    '-c:a', 'aac', '-b:a', '64k',
    '-movflags', '+faststart',
    dest,
  ]);
}

const ART_STYLE_PROMPTS = {
  cinematic:  'cinematic film quality, dramatic lighting, high contrast, professional cinematography',
  creepy:     'dark horror atmosphere, eerie gothic shadows, unsettling mood, sinister ambiance',
  vibrant:    'vibrant colorful scene, bold energetic colors, pop art style, dynamic motion',
  disney:     'Disney Pixar 3D animation style, magical whimsical, warm lighting',
  nature:     'stunning nature footage, lush landscape, golden hour lighting, ultra detailed',
  urban:      'urban street scene, neon night city lights, gritty atmosphere, cinematic',
  fantasy:    'epic fantasy scene, mystical ethereal glow, magical particles, cinematic',
  historical: 'historical period scene, period-accurate costumes, dramatic atmosphere',
  realistic:  'photorealistic footage, natural lighting, true-to-life colors, documentary style',
};

async function generateOneClip(prompt, clipDuration, artStyle, index) {
  const styleDesc  = ART_STYLE_PROMPTS[artStyle] || ART_STYLE_PROMPTS.cinematic;
  const fullPrompt = `${styleDesc}: ${prompt}. Vertical 9:16 portrait composition. Cinematic motion. No text, no subtitles, no watermarks.`;

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${process.env.XAI_API_KEY}`,
  };

  const res = await fetch(`${XAI_BASE}/videos/generations`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model:        'grok-imagine-video',
      prompt:       fullPrompt,
      duration:     clipDuration,
      aspect_ratio: '9:16',
      resolution:   '720p',
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    // Surface a clean message for common xAI errors
    try {
      const parsed = JSON.parse(body);
      const msg    = parsed.error || parsed.message || body;
      if (/credits|spending limit|exhausted/i.test(msg)) {
        throw new Error(`xAI account out of credits. Please top up at console.x.ai (clip ${index + 1})`);
      }
      throw new Error(`xAI video failed (clip ${index + 1}): ${msg}`);
    } catch (e) {
      if (e.message.startsWith('xAI')) throw e;
      throw new Error(`xAI video start failed (clip ${index + 1}): ${body}`);
    }
  }

  const { request_id } = await res.json();

  const deadline = Date.now() + 20 * 60 * 1000;  // 20 min timeout per clip
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 10000));  // poll every 10s

    const poll = await fetch(`${XAI_BASE}/videos/${request_id}`, {
      headers: { 'Authorization': `Bearer ${process.env.XAI_API_KEY}` },
    });
    const data = await poll.json();

    if (data.status === 'done')    return data.video.url;
    if (data.status === 'expired') throw new Error(`xAI video request expired (clip ${index + 1})`);
    if (data.status === 'failed')  throw new Error(`xAI video generation failed (clip ${index + 1})`);
    // status === 'pending' — keep polling
  }

  throw new Error(`xAI video generation timed out (clip ${index + 1})`);
}

/**
 * Generate AI video clips using xAI grok-imagine-video.
 * Clips are generated in parallel and downloaded locally.
 *
 * @param {string[]} scriptLines  - script lines (split by newline, filtered)
 * @param {number}   reelId
 * @param {string}   artStyle     - e.g. 'cinematic', 'creepy'
 * @param {string}   duration     - '30-40' or '60-70'
 * @returns {Promise<{ clipPaths: string[], audioDurations: number[] }>}
 */
export async function generateVideoClips(scriptLines, reelId, artStyle = 'cinematic', duration = '30-40', provider = 'xai', personImagePath = null) {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  await fsp.mkdir(dir, { recursive: true });

  const clipSec = 8; // Veo always generates 8s clips
  const WPM     = 175;

  // Group sentences so each clip covers ~8s of narration (175 WPM × 8/60 ≈ 23 words)
  const WORDS_PER_CLIP = 23;
  const fullText  = scriptLines.join(' ');
  const sentences = fullText
    .split(/(?<=[.!?])\s+/)
    .map(s => s.trim())
    .filter(s => s.length > 10);

  const chunks = [];
  let group = [], groupWords = 0;
  for (const sentence of sentences) {
    const words = sentence.split(/\s+/).length;
    if (groupWords + words > WORDS_PER_CLIP * 1.5 && group.length > 0) {
      chunks.push(group.join(' ').substring(0, 500));
      group = [sentence];
      groupWords = words;
    } else {
      group.push(sentence);
      groupWords += words;
    }
  }
  if (group.length) chunks.push(group.join(' ').substring(0, 500));

  // Fallback: if sentence splitting failed, use full text as one chunk
  if (!chunks.length) chunks.push(fullText.substring(0, 500));

  // Clip count is now driven by the script, not hardcoded
  const count = chunks.length;

  // Per-clip audio duration estimated from word count
  const audioDurations = chunks.map(chunk => {
    const words = chunk.split(/\s+/).filter(Boolean).length;
    return Math.max(+(words / WPM * 60).toFixed(2), 3);
  });

  // ── Mock mode: generate solid-black test clips via FFmpeg, no xAI needed ────
  if (process.env.XAI_MOCK === 'true') {
    console.log(`[VideoGen] Reel #${reelId}: MOCK mode — generating ${count} test clips…`);
    const clipPaths = await Promise.all(
      Array.from({ length: count }, async (_, i) => {
        const dest = path.join(dir, `clip_${i}.mp4`);
        await makeMockClip(dest, clipSec);
        console.log(`[VideoGen] Mock clip ${i + 1}/${count} generated`);
        return dest;
      })
    );
    return { clipPaths, audioDurations };
  }

  // Rewrite narration chunks as cinematic visual scene descriptions (used by both providers)
  console.log(`[VideoGen] Reel #${reelId}: ${count} sentence-driven clips, rewriting as visual scenes…`);
  const rawVisualChunks = await rewriteChunksAsVisualScenes(chunks, artStyle);
  // Sanitize AFTER Gemini rewrite — Gemini can re-introduce filtered terms (scourged, crucified, etc.)
  const visualChunks = rawVisualChunks.map(sanitizeForVeo);

  let clipPaths;
  if (provider === 'sora-2' || provider === 'sora-2-pro') {
    clipPaths = await generateClipsViaSora(visualChunks, count, provider, dir, reelId);
  } else if (provider === 'veo') {
    clipPaths = await generateClipsViaVeo(visualChunks, count, dir, reelId, personImagePath);
  } else {
    clipPaths = await generateClipsViaXAI(visualChunks, count, clipSec, artStyle, dir, reelId);
  }

  return { clipPaths, audioDurations };
}

// ── xAI clip generation ───────────────────────────────────────────────────────
async function generateClipsViaXAI(chunks, count, clipSec, artStyle, dir, reelId) {
  console.log(`[VideoGen] Reel #${reelId}: generating ${count} xAI clips in parallel (${clipSec}s each)…`);
  const clipUrls = await Promise.all(
    chunks.map(async (chunk, i) => {
      for (let attempt = 1; attempt <= 2; attempt++) {
        try {
          const url = await generateOneClip(chunk, clipSec, artStyle, i);
          console.log(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ready`);
          return url;
        } catch (err) {
          if (attempt === 2) throw err;
          console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ${err.message} — retrying…`);
        }
      }
    })
  );
  return Promise.all(
    clipUrls.map((url, i) => {
      const dest = path.join(dir, `clip_${i}.mp4`);
      return downloadFile(url, dest)
        .then(() => { console.log(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: downloaded`); return dest; });
    })
  );
}

// ── OpenAI Sora clip generation ───────────────────────────────────────────────
async function generateClipsViaSora(chunks, count, soraModel, dir, reelId) {
  const size    = soraModel === 'sora-2-pro' ? '1024x1792' : '720x1280';
  const seconds = '8';  // valid values: "4", "8", "12"
  console.log(`[VideoGen] Reel #${reelId}: generating ${count} Sora clips (${soraModel}, ${size}, ${seconds}s)…`);

  return Promise.all(
    chunks.map(async (chunk, i) => {
      const dest = path.join(dir, `clip_${i}.mp4`);
      for (let attempt = 1; attempt <= 2; attempt++) {
        try {
          let job = await getOpenAI().videos.create({ model: soraModel, prompt: chunk, size, seconds });

          const deadline = Date.now() + 25 * 60 * 1000;
          while (job.status !== 'completed' && job.status !== 'failed') {
            if (Date.now() > deadline) throw new Error(`Sora timed out (clip ${i + 1})`);
            await new Promise(r => setTimeout(r, 15000));
            job = await getOpenAI().videos.retrieve(job.id);
          }
          if (job.status === 'failed') throw new Error(`Sora generation failed (clip ${i + 1})`);

          const content = await getOpenAI().videos.downloadContent(job.id);
          const buffer  = Buffer.from(await content.arrayBuffer());
          await fsp.writeFile(dest, buffer);
          console.log(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: Sora ready`);
          return dest;
        } catch (err) {
          if (attempt === 3) throw err;
          // On hard policy violation soften the prompt for next attempt
          if (attempt === 1 && /usage guidelines|violate|blocked/i.test(err.message)) {
            chunk = `A cinematic documentary scene: ${chunk.replace(/crime|murder|kill|death|blood|victim|suspect|violence|attack|shoot|stab|body|corpse|weapon|gun|knife/gi, 'incident').substring(0, 300)}`;
          }
          console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ${err.message.substring(0, 120)} — retrying…`);
        }
      }
    })
  );
}

// ── Prompt sanitiser — replaces terms that trigger Veo's RAI filter ─────────────
const SENSITIVE_TERMS = /\b(murder|kill(?:ing|ed|s)?|blood(?:y)?|corpse|shoot(?:ing)?|shot|stab(?:bing)?|bomb(?:ing)?|gore|mutilat(?:e|ion|ed)|beheading|decapitat(?:e|ion|ed)|torture|scourg(?:ed|ing)?|crucif(?:y|ix|ied|ixion|ying)?|cross\s*beam|bearing\s*(?:a\s*)?cross|nailed\s*to|lash(?:ed|ing)?|flog(?:ged|ging)?|slaughter|massacre|execut(?:ion|e|ed|ing)?|wound(?:ed|ing)?|mortal(?:ly)?|dy(?:ing|e[ds]?)|bleed(?:ing)?|death|dead(?:ly)?|persecut(?:e[ds]?|ing|ion)|martyr(?:s|dom)?|sacrific(?:e[ds]?|ing|ial)|suffer(?:ing|ed|s)?|condemn(?:ed|ation)?|punish(?:ment|ed|ing)?|agon(?:y|izing)|hang(?:ed|ing)|impaled?|stoned|crucify|missile(?:s)?|rocket(?:s)?|launch\s*(?:pad|vehicle)?|spacecraft|satellite(?:s)?|test\s*range|weapon(?:s|ry)?|warhead(?:s)?|warship(?:s)?|nuclear(?:\s+\w+)?|ballistic|armament(?:s)?|munition(?:s)?|detonat(?:e|ion|ing|ed)?|explos(?:ive|ion)|combat|warfare|armed\s+forces|military\s+(?:base|camp|operation|personnel|force)|soldier(?:s)?|army|navy|air\s*force|fighter\s+(?:jet|plane|aircraft)|warplane|gunship|canno(?:n|nade)|artillery|grenade|sniper|hostage|terrorist(?:s|ism)?|jihad|poverty|slum(?:s)?|destitute|impoverished|starv(?:ing|ation)|oppres(?:s(?:ed|ion|ing))?|zombie|vampire|undead|poltergeist|satan(?:ic)?|occult|witch(?:craft)?|porn|nude|naked|sexual|explicit)\b/gi;

const NEUTRAL_MAP = {
  murder:      'tragedy',
  kill:        'overcome',
  bloody:      'intense',
  blood:       'offering',
  corpse:      'fallen figure',
  shooting:    'conflict',
  shot:        'struck',
  stabbing:    'confrontation',
  stab:        'confrontation',
  bombing:     'explosion',
  bomb:        'explosion',
  gore:        'intensity',
  mutilate:    'struggle',
  beheading:   'ancient trial',
  decapitate:  'ancient punishment',
  torture:     'ordeal',
  scourged:    'weary',
  scourging:   'struggle',
  crucif:      'solemn moment',
  crucify:     'solemn moment',
  'cross beam':'heavy burden',
  'bearing':   'carrying',
  nailed:      'bound',
  lashed:      'weary',
  lashing:     'struggle',
  flogged:     'weary',
  flogging:    'hardship',
  slaughter:   'conflict',
  massacre:    'tragedy',
  execut:      'judgment',
  wounded:     'weary',
  wounding:    'struggle',
  mortally:    'gravely',
  dying:       'at peace',
  'dye':       'at peace',
  'died':      'passed',
  'die':       'depart',
  'dies':      'departs',
  death:       'final chapter',
  dead:        'still',
  deadly:      'intense',
  persecuted:  'tested',
  persecuting: 'challenging',
  persecution: 'hardship',
  persecute:   'challenge',
  martyr:      'devoted follower',
  martyrdom:   'devotion',
  sacrifice:   'offering',
  sacrificial: 'ceremonial',
  suffering:   'hardship',
  suffered:    'endured',
  condemned:   'judged',
  condemnation:'judgment',
  punished:    'corrected',
  punishment:  'consequence',
  agony:       'anguish',
  agonizing:   'intense',
  hanged:      'bound',
  hanging:     'suspended',
  impaled:     'struck',
  stoned:      'confronted',
  bleeding:    'weary',
  // Space / aerospace terms Gemini produces for ISRO / Kalam scripts
  rocket:      'aerospace vehicle',
  'launch vehicle': 'aerospace vehicle',
  spacecraft:  'aerial vehicle',
  satellite:   'scientific device',
  'launch pad': 'research platform',
  'test range': 'research facility',
  warship:     'vessel',
  soldier:     'person',
  soldiers:    'people',
  army:        'national organisation',
  navy:        'national organisation',
  'air force': 'national organisation',
  tank:        'vehicle',
  // Poverty / hardship terms that trigger visual filter
  poverty:     'humble surroundings',
  slum:        'modest neighbourhood',
  destitute:   'humble',
  impoverished:'modest',
  starving:    'determined',
  starvation:  'hardship',
  oppression:  'challenge',
  oppressed:   'challenged',
  missile:     'aerospace vehicle',
  missiles:    'aerospace vehicles',
  weapon:      'technology',
  weapons:     'technologies',
  weaponry:    'technology',
  warhead:     'scientific device',
  warheads:    'scientific devices',
  nuclear:     'advanced scientific',
  ballistic:   'aerospace',
  armament:    'achievement',
  armaments:   'achievements',
  munition:    'device',
  munitions:   'devices',
  detonate:    'activate',
  detonation:  'activation',
  detonating:  'activating',
  detonated:   'activated',
  explosive:   'powerful',
  explosion:   'launch',
  combat:      'national effort',
  warfare:     'national effort',
  'armed forces': 'national organisation',
  'military base': 'research facility',
  'military camp': 'research campus',
  'military operation': 'national project',
  'military personnel': 'scientists and engineers',
  'military force': 'national team',
  'fighter jet': 'aircraft',
  'fighter plane': 'aircraft',
  'fighter aircraft': 'aircraft',
  warplane:    'aircraft',
  gunship:     'aircraft',
  cannon:      'instrument',
  artillery:   'equipment',
  grenade:     'device',
  sniper:      'observer',
  hostage:     'person',
  terrorist:   'person',
  terrorists:  'people',
  terrorism:   'challenge',
  jihad:       'pursuit',
  zombie:      'wandering figure',
  vampire:     'mysterious figure',
  undead:      'mysterious figure',
  poltergeist: 'mysterious force',
  satanic:     'ancient',
  satan:       'dark force',
  occult:      'ancient ritual',
  witchcraft:  'ancient practice',
  witch:       'enigmatic figure',
};

function sanitizeForVeo(prompt) {
  return prompt.replace(SENSITIVE_TERMS, match => {
    const lower = match.toLowerCase().replace(/\s+/g, ' ');
    const key = Object.keys(NEUTRAL_MAP).find(k => lower.startsWith(k));
    return key ? NEUTRAL_MAP[key] : 'solemn moment';
  });
}

// Neutral documentary b-roll used when ALL retry attempts are blocked by Veo input filter
const NEUTRAL_BROLL = [
  'Aerial slow-motion shot of a coastal Indian town at golden hour, colourful fishing boats, warm light, photorealistic documentary.',
  'Close-up of a student writing equations in a notebook, warm lamplight, focused expression, cinematic.',
  'Wide establishing shot of a large government research campus surrounded by lush greenery, institutional, peaceful.',
  'A young man in simple clothes cycling through a quiet village road at dawn, golden light, aspirational mood.',
  'Slow cinematic pan over a modern science campus with tall trees, researchers walking, soft morning light.',
  'A solitary figure in formal attire standing on a stage facing an audience, soft spotlight, inspirational.',
  'Close-up of hands turning the pages of a thick engineering textbook, warm tones, academic atmosphere.',
  'Aerial shot of rural Tamil Nadu coastline, blue ocean, fishing villages, golden hour, documentary style.',
  'Interior of a large university laboratory, students at workstations with computers, warm professional lighting.',
  'Slow pan across a wall of awards, certificates and framed photographs, warm ambient light, pride and legacy.',
  'A crowd of students gathered in an open auditorium, attentive, inspired expressions, warm natural light.',
  'Wide shot of a grand government building at dawn, national flag waving, soft morning light.',
  'Close-up of a person writing notes at a wooden desk near a window, sunlight streaming in, focused and calm.',
  'Aerial view of a green Indian village, terracotta rooftops, palm trees, golden morning light.',
  'A mentor and student in conversation under a large tree on a university campus, warm afternoon light.',
];

function neutralFallback(clipIndex) {
  return NEUTRAL_BROLL[clipIndex % NEUTRAL_BROLL.length];
}

// ── Google Veo 3.1 clip generation ───────────────────────────────────────────
// Semaphore: at most N concurrent Veo operations (avoids 429 quota on large reels)
function makeSemaphore(max) {
  let active = 0;
  const queue = [];
  return function acquire() {
    return new Promise(resolve => {
      const tryRun = () => {
        if (active < max) { active++; resolve(() => { active--; if (queue.length) queue.shift()(); }); }
        else queue.push(tryRun);
      };
      tryRun();
    });
  };
}
const VEO_CONCURRENCY = 3; // Vertex AI quota: safe concurrency to avoid per-minute 429s

async function generateClipsViaVeo(chunks, count, dir, reelId, personImagePath = null) {
  console.log(`[VideoGen] Reel #${reelId}: generating ${count} Veo clips${personImagePath ? ' (image-to-video)' : ''} — max ${VEO_CONCURRENCY} concurrent…`);
  const client  = getVeoClient();
  const acquire = makeSemaphore(VEO_CONCURRENCY);

  // Load person image once as base64 (if provided)
  let personImageData = null;
  if (personImagePath) {
    try {
      const buf  = await fsp.readFile(personImagePath);
      const ext  = path.extname(personImagePath).toLowerCase().replace('.', '') || 'jpeg';
      const mime = ext === 'png' ? 'image/png' : ext === 'webp' ? 'image/webp' : 'image/jpeg';
      personImageData = { imageBytes: buf.toString('base64'), mimeType: mime };
      console.log(`[VideoGen] Reel #${reelId}: person image loaded (${buf.length} bytes, ${mime})`);
    } catch (e) {
      console.warn(`[VideoGen] Reel #${reelId}: could not load person image — ${e.message}. Falling back to text-only.`);
    }
  }

  return Promise.all(
    chunks.map(async (chunk, i) => {
      const release = await acquire(); // wait for a slot
      // Stagger requests within each batch by 2s to prevent quota burst
      await new Promise(r => setTimeout(r, (i % VEO_CONCURRENCY) * 2000));
      const dest = path.join(dir, `clip_${i}.mp4`);
      let prompt    = chunk; // already sanitized before entering this function

      const original = chunk;
      let wasBlocked = false; // true if Veo rejected the prompt at input level

      for (let attempt = 1; attempt <= 3; attempt++) {
        if (attempt === 2) {
          // If Veo blocked the prompt at input level, jump straight to neutral b-roll
          // (shorter version of the same blocked content will also be blocked)
          prompt = wasBlocked
            ? neutralFallback(i)
            : sanitizeForVeo(`Cinematic scene: ${original.substring(0, 250)}`);
        }
        if (attempt === 3) {
          prompt = neutralFallback(i); // guaranteed-safe fallback
        }

        try {
          // Build request — include person image on attempt 1 and 2 (skip on attempt 3 fallback)
          const useImage = personImageData && attempt <= 2;
          const requestParams = {
            model: 'veo-2.0-generate-001', // veo-2 has stable image-to-video support; veo-3.1 text-only
            prompt,
            config: {
              aspectRatio:      '9:16',
              numberOfVideos:   1,
              durationSeconds:  8,
              personGeneration: 'allow_all',
              resolution:       '720p',
              generateAudio:    false,
            },
          };
          // Use veo-3.1 only when there's no person image (text-to-video)
          if (!useImage) requestParams.model = 'veo-3.1-generate-001';
          if (useImage)  requestParams.image  = personImageData;

          let operation = await client.models.generateVideos(requestParams);

          const deadline = Date.now() + 25 * 60 * 1000;
          while (!operation.done) {
            if (Date.now() > deadline) throw new Error(`Veo timed out (clip ${i + 1})`);
            await new Promise(r => setTimeout(r, 10000));
            operation = await client.operations.getVideosOperation({ operation });
          }

          if (operation.error) throw new Error(`Veo failed (clip ${i + 1}): ${operation.error.message || JSON.stringify(operation.error)}`);

          const generatedVideo = operation.response?.generatedVideos?.[0];
          const filteredCount  = operation.response?.raiMediaFilteredCount || 0;

          if (!generatedVideo) {
            if (filteredCount > 0) {
              const reasons = operation.response?.raiMediaFilteredReasons?.join(', ') || 'policy';
              console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: filtered (${reasons}) — retrying with softer prompt…`);
              throw new Error(`filtered:${reasons}`);
            }
            throw new Error(`Veo returned no video (clip ${i + 1})`);
          }

          await client.files.download({ file: generatedVideo, downloadPath: dest });
          console.log(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: Veo ready`);
          release();
          return dest;
        } catch (err) {
          if (attempt === 3) { release(); throw err; }
          if (/could not be submitted|contains words|violate.*guidelines/i.test(err.message)) {
            wasBlocked = true; // switch to neutral b-roll on next attempt
          }
          // On 429 quota error wait longer before retry
          const is429 = /429|Quota exceeded/i.test(err.message);
          if (is429) await new Promise(r => setTimeout(r, 45_000));
          else {
            const isNetworkErr = /fetch failed|ECONNRESET|ETIMEDOUT|socket|network/i.test(err.message);
            if (isNetworkErr) await new Promise(r => setTimeout(r, 5000));
          }
          console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ${err.message.substring(0, 120)} — retrying (${attempt}/3)…`);
        }
      }
      release(); // safety — ensure release even if loop exits without returning
    })
  );
}

/**
 * Delete the temp clip directory for a reel.
 */
export async function cleanupTempVideos(reelId) {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  try { await fsp.rm(dir, { recursive: true, force: true }); } catch {}
}

// ── Internal: download a URL to a local file ──────────────────────────────────
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const file  = fs.createWriteStream(dest);

    const req = proto.get(url, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        file.close();
        fsp.unlink(dest).catch(() => {});
        return downloadFile(res.headers.location, dest).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        reject(new Error(`Download failed: HTTP ${res.statusCode}`));
        return;
      }
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
    });

    req.on('error', err => { file.close(); fsp.unlink(dest).catch(() => {}); reject(err); });
    req.setTimeout(120000, () => { req.destroy(); reject(new Error('Video download timed out')); });
  });
}
