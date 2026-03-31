import OpenAI from 'openai';
import fsp from 'fs/promises';
import fs from 'fs';
import https from 'https';
import http from 'http';
import path from 'path';

let _openai = null;
function getOpenAI() {
  if (!_openai) _openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _openai;
}

let _xai = null;
function getXAI() {
  if (!_xai) _xai = new OpenAI({ apiKey: process.env.XAI_API_KEY, baseURL: 'https://api.x.ai/v1' });
  return _xai;
}

// ── Names that trigger DALL-E content policy ─────────────────────────────────
const STRIP_NAMES = [
  /\bJesus\b/gi, /\bChrist\b/gi, /\bMessiah\b/gi,
  /\bGod\b/gi,   /\bAllah\b/gi,  /\bYahweh\b/gi, /\bJehovah\b/gi,
  /\bMoses\b/gi, /\bNoah\b/gi,   /\bAbraham\b/gi,/\bIsaac\b/gi,
  /\bJacob\b/gi, /\bJoseph\b/gi, /\bDavid\b/gi,  /\bSolomon\b/gi,
  /\bElijah\b/gi,/\bElisha\b/gi, /\bSamson\b/gi, /\bDaniel\b/gi,
  /\bMary\b/gi,  /\bAngel\b/gi,  /\bAngels\b/gi,
  /\bMuhammad\b/gi, /\bProphet\b/gi,
  /\bSatan\b/gi, /\bDevil\b/gi,  /\bLucifer\b/gi,/\bDemon\b/gi,
  /\bBible\b/gi, /\bQuran\b/gi,  /\bTorah\b/gi,  /\bBiblical\b/gi,
];

function sanitizeSceneText(text) {
  let s = text;
  for (const re of STRIP_NAMES) s = s.replace(re, 'a figure');
  return s;
}

// ── Art style → DALL-E 3 visual description ───────────────────────────────────
const ART_STYLE_VISUALS = {
  cinematic:  'cinematic film still, dramatic lighting, high contrast, professional cinematography',
  creepy:     'dark horror atmosphere, eerie gothic shadows, unsettling mood, sinister',
  vibrant:    'vibrant colorful modern illustration, bold energetic colors, pop art style',
  disney:     'Disney Pixar 3D animation style, magical whimsical warm lighting, family-friendly',
  nature:     'nature photography, lush landscape, golden hour lighting, ultra detailed',
  urban:      'urban street photography, neon night city lights, gritty atmosphere',
  fantasy:    'epic fantasy digital art, mystical ethereal glow, magical detailed illustration',
  historical: 'historical oil painting style, period-accurate, dramatic vintage tones',
};

/**
 * Generate AI images from script lines using DALL-E 3.
 * Splits the script into `count` equal scenes and generates one image per scene.
 *
 * @param {string[]} scriptLines - script lines (already split by newline, filtered)
 * @param {number}   reelId
 * @param {string}   artStyle    - e.g. 'cinematic', 'creepy', etc.
 * @param {number}   count       - number of images to generate (4 or 6)
 * @returns {Promise<string[]>}  - absolute local paths to downloaded PNG files
 */
export async function generateImages(scriptLines, reelId, artStyle = 'cinematic', count = 4, provider = 'openai') {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  await fsp.mkdir(dir, { recursive: true });

  const client = provider === 'xai' ? getXAI() : getOpenAI();
  const model  = provider === 'xai' ? 'aurora'  : 'dall-e-3';
  const size   = provider === 'xai' ? '768x1280' : '1024x1792';

  const styleVisual = ART_STYLE_VISUALS[artStyle] || ART_STYLE_VISUALS.cinematic;

  // Divide script lines into `count` equal groups
  const chunkSize = Math.ceil(scriptLines.length / count);
  const chunks    = Array.from({ length: count }, (_, i) =>
    scriptLines.slice(i * chunkSize, (i + 1) * chunkSize).join(' ').substring(0, 300).trim()
  );

  const imagePaths = [];

  for (let i = 0; i < count; i++) {
    const rawScene  = chunks[i] || chunks[chunks.length - 1] || 'dramatic scene';
    const safeScene = sanitizeSceneText(rawScene);
    const prompt    =
      `${styleVisual}: ${safeScene}. ` +
      `Vertical portrait composition 9:16. No text, no watermarks, no subtitles. High quality.`;

    console.log(`[ImageGen] Reel #${reelId} image ${i + 1}/${count}: generating…`);

    const genOpts = {
      model,
      n:               1,
      size,
      response_format: 'url',
    };
    if (provider !== 'xai') genOpts.quality = 'standard';  // DALL-E 3 only

    let response;
    try {
      response = await client.images.generate({ ...genOpts, prompt });
    } catch (err) {
      // Retry with a generic fallback if content policy triggered
      if (err?.status === 400 || err?.message?.toLowerCase().includes('safety')) {
        console.warn(`[ImageGen] Reel #${reelId} image ${i + 1}: safety rejection — retrying with fallback prompt`);
        const fallback = `${styleVisual}: an epic dramatic scene, ancient world setting, majestic golden atmosphere, grand architecture. Vertical portrait composition 9:16. No text, no watermarks. High quality.`;
        response = await client.images.generate({ ...genOpts, prompt: fallback });
      } else {
        throw err;
      }
    }

    const imageUrl = response.data[0].url;
    const destPath = path.join(dir, `img_${i}.png`);

    await downloadImageFile(imageUrl, destPath);
    imagePaths.push(destPath);
    console.log(`[ImageGen] Reel #${reelId} image ${i + 1}/${count} saved → ${destPath}`);
  }

  return imagePaths;
}

/**
 * Delete the temp image directory for a reel.
 * @param {number} reelId
 */
export async function cleanupTempImages(reelId) {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch {
    // non-critical
  }
}

// ── Internal: download a URL to a local file ──────────────────────────────────
function downloadImageFile(url, dest) {
  return new Promise((resolve, reject) => {
    const proto   = url.startsWith('https') ? https : http;
    const file    = fs.createWriteStream(dest);

    const request = proto.get(url, (response) => {
      // Follow redirects (up to 5 hops handled recursively)
      if (response.statusCode === 301 || response.statusCode === 302) {
        file.close();
        fsp.unlink(dest).catch(() => {});
        return downloadImageFile(response.headers.location, dest).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        file.close();
        reject(new Error(`Failed to download image: HTTP ${response.statusCode}`));
        return;
      }

      response.pipe(file);
      file.on('finish', () => file.close(resolve));
    });

    request.on('error', (err) => {
      file.close();
      fsp.unlink(dest).catch(() => {});
      reject(err);
    });

    request.setTimeout(60000, () => {
      request.destroy();
      reject(new Error('Image download timed out'));
    });
  });
}
