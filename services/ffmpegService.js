import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import path from 'path';
import fs from 'fs/promises';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// ── Caption style drawtext configurations ─────────────────────────────────────
const CAPTION_STYLES = {
  'bold-stroke':   'fontsize=64:fontcolor=white:borderw=5:bordercolor=black',
  'red-highlight': 'fontsize=60:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=red@0.85:boxborderw=12',
  'sleek':         'fontsize=48:fontcolor=white:borderw=2:bordercolor=black@0.5',
  'majestic':      'fontsize=68:fontcolor=gold:borderw=4:bordercolor=black',
  'beast':         'fontsize=72:fontcolor=yellow:borderw=6:bordercolor=black',
  'elegant':       'fontsize=54:fontcolor=white:borderw=2:bordercolor=black@0.6',
  'clarity':       'fontsize=58:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=black@0.5:boxborderw=10',
  'karaoke':       'fontsize=64:fontcolor=white:borderw=0:box=1:boxcolor=0x7c3aed@0.92:boxborderw=14',
};

// ── Sanitize a single line for use inside FFmpeg drawtext ────────────────────
function sanitizeLine(text) {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/'/g, '\u2019')      // typographic apostrophe — safe in drawtext
    .replace(/:/g, '\\:')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]');
}

// ── Build timed subtitle segments from a line-per-line script ────────────────
// Splits script into 3-word groups with estimated timing at ~155 WPM.
// Produces TikTok-style captions that change every ~1s as audio plays.
function buildSubtitleSegments(script) {
  const WPM         = 155;
  const secsPerWord = 60 / WPM;
  const lines       = script.split(/\n+/).map(l => l.trim()).filter(Boolean);
  const segments    = [];
  let t = 0;

  lines.forEach(line => {
    const words = line.split(/\s+/).filter(Boolean);
    for (let i = 0; i < words.length; i += 3) {
      const group    = words.slice(i, i + 3);
      const duration = Math.max(group.length * secsPerWord, 0.5);
      segments.push({
        text:  sanitizeLine(group.join(' ')),
        start: +t.toFixed(2),
        end:   +(t + duration).toFixed(2),
      });
      t += duration;
    }
  });

  return segments;
}

/**
 * Merge video clips + TTS audio into a single vertical MP4 reel.
 *
 * Pipeline:
 *   1. Scale each clip to 1080×1920 (portrait), pad/crop as needed
 *   2. Concatenate all clips
 *   3. Optionally apply shake effect
 *   4. Burn timed subtitle text (one line per script line, synced to ~155 WPM)
 *   5. Optionally apply film grain effect
 *   6. Mix TTS audio with optional BGM at 15% volume
 *   7. Export with fast libx264 / aac encoding
 *
 * @param {number}   reelId       - used to name the output file
 * @param {string[]} clipPaths    - local paths to downloaded video clips
 * @param {string}   audioPath   - local path to TTS mp3
 * @param {string}   script      - line-per-line script used for timed subtitles
 * @param {object}   options
 * @param {string}   [options.captionStyle='bold-stroke']
 * @param {object}   [options.effects]
 * @param {boolean}  [options.effects.filmGrain=false]
 * @param {boolean}  [options.effects.shake=false]
 * @param {string}   [options.musicPath=null]  - absolute path to BGM mp3, or null
 * @returns {Promise<string>}   resolved output file path
 */
/**
 * Pan animation variants — cycled per image for visual variety.
 * Uses scale+crop with t-based expressions instead of zoompan to avoid PTS issues.
 * Scale to 120% (1296×2304) then crop the 1080×1920 window, shifting by t.
 */
const PAN_VARIANTS = [
  { x: `(iw-ow)/2`,                             y: `(ih-oh)*min(t/D,1)` },    // top→bottom
  { x: `(iw-ow)/2`,                             y: `(ih-oh)*max(1-t/D,0)` },  // bottom→top
  { x: `(iw-ow)*min(t/D,1)`,                    y: `(ih-oh)/2` },              // left→right
  { x: `(iw-ow)*max(1-t/D,0)`,                  y: `(ih-oh)/2` },              // right→left
];

/**
 * Merge AI-generated images + TTS audio into a single vertical MP4 reel.
 *
 * Pipeline:
 *   1. Loop each image as a still-image stream (11s or 13s per image)
 *   2. Scale each image to 1080×1920 portrait
 *   3. Apply Ken Burns (zoompan) animation — cycling through 4 pan/zoom variants
 *   4. Concatenate all animated clips
 *   5. Optionally apply shake effect
 *   6. Burn timed subtitle text synced to ~155 WPM
 *   7. Optionally apply film grain
 *   8. Mix TTS audio with optional BGM at 15% volume
 *   9. Export with libx264 / aac — `-shortest` trims to TTS audio length
 *
 * @param {number}   reelId
 * @param {string[]} imagePaths  - local paths to PNG images (4 or 6)
 * @param {string}   audioPath  - local path to TTS mp3
 * @param {string}   script     - line-per-line script used for timed subtitles
 * @param {object}   options
 * @param {string}   [options.captionStyle='bold-stroke']
 * @param {object}   [options.effects]
 * @param {boolean}  [options.effects.filmGrain=false]
 * @param {boolean}  [options.effects.shake=false]
 * @param {string}   [options.musicPath=null]
 * @param {string}   [options.duration='30-40']  - '30-40' or '60-70'
 * @returns {Promise<string>}  resolved output file path
 */
export async function mergeReelFromImages(reelId, imagePaths, audioPath, script, options = {}) {
  const {
    captionStyle = 'bold-stroke',
    effects      = {},
    musicPath    = null,
    duration     = '30-40',
  } = options;

  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const captionParams = CAPTION_STYLES[captionStyle] || CAPTION_STYLES['bold-stroke'];
  const grainFilter   = effects.filmGrain ? ',noise=alls=20:allf=t' : '';
  const hasShake      = !!effects.shake;
  const hasBGM        = !!musicPath;

  // Seconds each image is held on screen — total must exceed TTS audio length
  // (-shortest will cut at audio end)
  const frameDuration = duration === '60-70' ? 13 : 11;

  const n = imagePaths.length;  // audio stream index = n, BGM = n+1

  const segments = buildSubtitleSegments(script);

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Each image: loop as still-image stream for frameDuration seconds
    imagePaths.forEach((p) => {
      cmd.input(p).inputOptions(['-loop 1', `-t ${frameDuration}`]);
    });
    cmd.input(audioPath);
    if (hasBGM) {
      cmd.input(musicPath);
      console.log(`[FFmpeg] BGM mixed: ${path.basename(musicPath)}`);
    }

    // Per-image: scale to exact 1080×1920, then scale to 120% for pan headroom,
    // then animated crop — explicit format=yuv420p avoids encoder pixel format errors
    const imageFilters = imagePaths.map((_, i) => {
      const pan = PAN_VARIANTS[i % PAN_VARIANTS.length];
      const px  = pan.x.replace(/D/g, frameDuration);
      const py  = pan.y.replace(/D/g, frameDuration);
      return (
        `[${i}:v]` +
        `scale=1080:1920:force_original_aspect_ratio=increase,` +
        `crop=1080:1920,` +
        `scale=1296:2304,` +
        `crop=1080:1920:x='${px}':y='${py}',` +
        `format=yuv420p,setsar=1,fps=24` +
        `[v${i}]`
      );
    });

    const concatInputLabels = imagePaths.map((_, i) => `[v${i}]`).join('');

    // Optional shake (same as mergeReel)
    const shakeStage  = hasShake
      ? `[vcat]scale=1116:1996,crop=1080:1920:x='18+18*sin(t*4)':y='18+18*sin(t*3)'[vshaken]`
      : null;
    const drawtextSrc = hasShake ? '[vshaken]' : '[vcat]';

    // Timed subtitle filters (identical logic to mergeReel)
    let subtitleFilters;
    if (segments.length <= 1) {
      const fallbackText = sanitizeLine(
        script.replace(/[\r\n]+/g, ' ').substring(0, 100).trim()
      );
      subtitleFilters = [
        `${drawtextSrc}drawtext=` +
        `text='${fallbackText}':` +
        `${captionParams}:` +
        `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1` +
        `${grainFilter}[vout]`,
      ];
    } else {
      subtitleFilters = segments.map((seg, i) => {
        const inputLabel  = i === 0 ? drawtextSrc : `[vsub${i - 1}]`;
        const isLast      = i === segments.length - 1;
        const outputLabel = isLast ? '[vout]' : `[vsub${i}]`;
        const grain       = isLast ? grainFilter : '';
        return (
          `${inputLabel}drawtext=` +
          `text='${seg.text}':` +
          `${captionParams}:` +
          `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1:` +
          `enable='between(t,${seg.start},${seg.end})':` +
          `alpha='min(1,max(0,if(lt(t,${seg.start}+0.2),(t-${seg.start})/0.2,if(gt(t,${seg.end}-0.15),(${seg.end}-t)/0.15,1))))'` +
          `${grain}${outputLabel}`
        );
      });
    }

    // Audio mix (identical to mergeReel)
    const audioFilterPart = hasBGM
      ? `[${n}:a]volume=1.0[tts];[${n + 1}:a]volume=0.15[bgm];[tts][bgm]amix=inputs=2:duration=first[aout]`
      : null;

    const filterComplex = [
      ...imageFilters,
      `${concatInputLabels}concat=n=${n}:v=1:a=0[vcat]`,
      ...(shakeStage      ? [shakeStage]      : []),
      ...subtitleFilters,
      ...(audioFilterPart ? [audioFilterPart] : []),
    ].join(';');

    const audioMap = hasBGM ? '-map [aout]' : `-map ${n}:a`;

    cmd
      .complexFilter(filterComplex)
      .outputOptions([
        '-map [vout]',
        audioMap,
        '-c:v libx264',
        '-c:a aac',
        '-b:a 128k',
        '-crf 26',
        '-preset ultrafast',
        '-r 24',
        '-threads 0',
        '-shortest',
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', () => console.log(`[FFmpeg] Starting image reel #${reelId}`))
      .on('progress', (p) => {
        if (p.percent) console.log(`[FFmpeg] Reel #${reelId}: ${Math.round(p.percent)}%`);
      })
      .on('end', () => {
        console.log(`[FFmpeg] Reel #${reelId} complete → ${outputPath}`);
        resolve(outputPath);
      })
      .on('error', (err, stdout, stderr) => {
        console.error(`[FFmpeg] Reel #${reelId} error:`, err.message);
        console.error('[FFmpeg stderr]', stderr);
        reject(new Error(`FFmpeg failed: ${err.message}`));
      })
      .run();
  });
}

export async function mergeReel(reelId, clipPaths, audioPath, script, options = {}) {
  const { captionStyle = 'bold-stroke', effects = {}, musicPath = null } = options;
  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);

  // Ensure output directory exists (Render ephemeral FS may not have it)
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const captionParams = CAPTION_STYLES[captionStyle] || CAPTION_STYLES['bold-stroke'];
  const grainFilter   = effects.filmGrain ? ',noise=alls=20:allf=t' : '';
  const hasShake      = !!effects.shake;
  const hasBGM        = !!musicPath;

  // Build timed subtitle segments from script lines
  const segments = buildSubtitleSegments(script);

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Inputs: video clips → TTS audio → (optional) BGM
    clipPaths.forEach((p) => cmd.input(p));
    cmd.input(audioPath);
    if (hasBGM) {
      cmd.input(musicPath);
      console.log(`[FFmpeg] BGM mixed: ${path.basename(musicPath)}`);
    }

    const n = clipPaths.length;  // TTS audio stream index = n, BGM = n+1

    // Scale/crop each clip to 1080×1920 portrait
    const scaleFilters = clipPaths.map(
      (_, i) =>
        `[${i}:v]` +
        `scale=1080:1920:force_original_aspect_ratio=increase,` +
        `crop=1080:1920,` +
        `setsar=1,` +
        `fps=30` +
        `[v${i}]`
    );

    const concatInputLabels = clipPaths.map((_, i) => `[v${i}]`).join('');

    // Shake: scale up slightly, crop with sinusoidal offset → camera wobble
    const shakeStage  = hasShake
      ? `[vcat]scale=1116:1996,crop=1080:1920:x='18+18*sin(t*4)':y='18+18*sin(t*3)'[vshaken]`
      : null;
    const drawtextSrc = hasShake ? '[vshaken]' : '[vcat]';

    // ── Timed subtitle filters ────────────────────────────────────────────────
    // Each segment gets its own drawtext with enable='between(t,start,end)'.
    // Filters are chained: drawtextSrc → [vsub0] → [vsub1] → … → [vout]
    // Film grain is appended only on the last filter in the chain.
    let subtitleFilters;
    if (segments.length <= 1) {
      // Fallback for scripts with no line breaks: show first 100 chars static
      const fallbackText = sanitizeLine(
        script.replace(/[\r\n]+/g, ' ').substring(0, 100).trim()
      );
      subtitleFilters = [
        `${drawtextSrc}drawtext=` +
        `text='${fallbackText}':` +
        `${captionParams}:` +
        `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1` +
        `${grainFilter}[vout]`,
      ];
    } else {
      subtitleFilters = segments.map((seg, i) => {
        const inputLabel  = i === 0 ? drawtextSrc : `[vsub${i - 1}]`;
        const isLast      = i === segments.length - 1;
        const outputLabel = isLast ? '[vout]' : `[vsub${i}]`;
        const grain       = isLast ? grainFilter : '';
        return (
          `${inputLabel}drawtext=` +
          `text='${seg.text}':` +
          `${captionParams}:` +
          `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1:` +
          `enable='between(t,${seg.start},${seg.end})':` +
          `alpha='min(1,max(0,if(lt(t,${seg.start}+0.2),(t-${seg.start})/0.2,if(gt(t,${seg.end}-0.15),(${seg.end}-t)/0.15,1))))'` +
          `${grain}${outputLabel}`
        );
      });
    }

    // ── Audio: optional BGM mix ───────────────────────────────────────────────
    // TTS at full volume + BGM at 15%, trimmed to TTS duration via amix duration=first
    const audioFilterPart = hasBGM
      ? `[${n}:a]volume=1.0[tts];[${n + 1}:a]volume=0.15[bgm];[tts][bgm]amix=inputs=2:duration=first[aout]`
      : null;

    const filterComplex = [
      ...scaleFilters,
      `${concatInputLabels}concat=n=${n}:v=1:a=0[vcat]`,
      ...(shakeStage        ? [shakeStage]        : []),
      ...subtitleFilters,
      ...(audioFilterPart   ? [audioFilterPart]   : []),
    ].join(';');

    const audioMap = hasBGM ? '-map [aout]' : `-map ${n}:a`;

    cmd
      .complexFilter(filterComplex)
      .outputOptions([
        '-map [vout]',
        audioMap,
        '-c:v libx264',
        '-c:a aac',
        '-b:a 128k',
        '-crf 26',
        '-preset ultrafast',
        '-r 30',
        '-shortest',
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', () => console.log(`[FFmpeg] Starting reel ${reelId}`))
      .on('progress', (p) => {
        if (p.percent) console.log(`[FFmpeg] Reel ${reelId}: ${Math.round(p.percent)}%`);
      })
      .on('end', () => {
        console.log(`[FFmpeg] Reel ${reelId} complete → ${outputPath}`);
        resolve(outputPath);
      })
      .on('error', (err, stdout, stderr) => {
        console.error(`[FFmpeg] Reel ${reelId} error:`, err.message);
        console.error('[FFmpeg stderr]', stderr);
        reject(new Error(`FFmpeg failed: ${err.message}`));
      })
      .run();
  });
}
