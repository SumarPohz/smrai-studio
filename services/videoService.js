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
// Prefers GOOGLE_API_KEY (Vertex AI Express key) over service-account JSON.
let _veoClient = null;
function getVeoClient() {
  if (_veoClient) return _veoClient;
  if (process.env.GOOGLE_API_KEY) {
    // Vertex AI Express — API key auth (simplest)
    _veoClient = new GoogleGenAI({ apiKey: process.env.GOOGLE_API_KEY });
  } else {
    // Service account fallback
    const opts = {
      vertexai: true,
      project:  process.env.GCP_PROJECT_ID || 'sumarbha-pohsnem',
      location: process.env.GCP_LOCATION   || 'us-central1',
    };
    if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      opts.googleAuthOptions = {
        credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      };
    }
    _veoClient = new GoogleGenAI(opts);
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
export async function generateVideoClips(scriptLines, reelId, artStyle = 'cinematic', duration = '30-40', provider = 'xai') {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  await fsp.mkdir(dir, { recursive: true });

  const count   = duration === '60-70' ? 8 : 5;
  const clipSec = duration === '60-70' ? 12 : 10;
  const WPM     = 150;

  // Divide script into `count` equal scene chunks
  const chunkSize = Math.ceil(scriptLines.length / count);
  const rawChunks = Array.from({ length: count }, (_, i) =>
    scriptLines.slice(i * chunkSize, (i + 1) * chunkSize).join(' ').substring(0, 400).trim()
  );
  // Fill any empty chunks (script shorter than clip count) by cycling non-empty ones
  const nonEmpty = rawChunks.filter(Boolean);
  const chunks   = rawChunks.map((c, i) => c || nonEmpty[i % nonEmpty.length] || scriptLines.join(' ').substring(0, 400));

  // Per-clip audio duration = word count at WPM — computed from original narration chunks
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
  console.log(`[VideoGen] Reel #${reelId}: rewriting ${count} chunks as visual scenes…`);
  const visualChunks = await rewriteChunksAsVisualScenes(chunks, artStyle);

  let clipPaths;
  if (provider === 'sora-2' || provider === 'sora-2-pro') {
    clipPaths = await generateClipsViaSora(visualChunks, count, provider, dir, reelId);
  } else if (provider === 'veo') {
    clipPaths = await generateClipsViaVeo(visualChunks, count, dir, reelId);
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
          if (attempt === 2) throw err;
          console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ${err.message} — retrying…`);
        }
      }
    })
  );
}

// ── Google Veo 3.1 clip generation ───────────────────────────────────────────
async function generateClipsViaVeo(chunks, count, dir, reelId) {
  console.log(`[VideoGen] Reel #${reelId}: generating ${count} Veo 3.1 clips…`);
  const client = getVeoClient();

  return Promise.all(
    chunks.map(async (chunk, i) => {
      const dest = path.join(dir, `clip_${i}.mp4`);
      for (let attempt = 1; attempt <= 2; attempt++) {
        try {
          let operation = await client.models.generateVideos({
            model: 'veo-3.1-generate-001',
            prompt: chunk,
            config: {
              aspectRatio:       '9:16',
              numberOfVideos:    1,
              durationSeconds:   8,
              personGeneration:  'allow_all',
              generateAudio:     false,
              resolution:        '720p',
            },
          });

          const deadline = Date.now() + 25 * 60 * 1000;
          while (!operation.done) {
            if (Date.now() > deadline) throw new Error(`Veo timed out (clip ${i + 1})`);
            await new Promise(r => setTimeout(r, 10000));
            operation = await client.operations.get(operation);
          }

          if (operation.error) throw new Error(`Veo failed (clip ${i + 1}): ${operation.error.message || JSON.stringify(operation.error)}`);

          const uri = operation.result?.generatedVideos?.[0]?.video?.uri;
          if (!uri) throw new Error(`Veo returned no video URI (clip ${i + 1})`);

          // URI is a signed GCS URL — download it
          await downloadFile(uri, dest);
          console.log(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: Veo ready`);
          return dest;
        } catch (err) {
          if (attempt === 2) throw err;
          console.warn(`[VideoGen] Reel #${reelId} clip ${i + 1}/${count}: ${err.message} — retrying…`);
        }
      }
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
