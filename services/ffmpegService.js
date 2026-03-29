import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import path from 'path';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// ── Caption style drawtext configurations ─────────────────────────────────────
const CAPTION_STYLES = {
  'bold-stroke':   'fontsize=52:fontcolor=white:borderw=5:bordercolor=black',
  'red-highlight': 'fontsize=48:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=red@0.85:boxborderw=10',
  'sleek':         'fontsize=36:fontcolor=white:borderw=2:bordercolor=black@0.5',
  'majestic':      'fontsize=56:fontcolor=gold:borderw=4:bordercolor=black',
  'beast':         'fontsize=60:fontcolor=yellow:borderw=6:bordercolor=black',
  'elegant':       'fontsize=42:fontcolor=white:borderw=2:bordercolor=black@0.6',
  'clarity':       'fontsize=46:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=black@0.5:boxborderw=8',
  'karaoke':       'fontsize=52:fontcolor=white:borderw=0:box=1:boxcolor=0x7c3aed@0.92:boxborderw=12',
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
// Estimates on-screen time per line at ~155 WPM.
function buildSubtitleSegments(script) {
  const WPM         = 155;
  const secsPerWord = 60 / WPM;
  const lines       = script.split(/\n+/).map(l => l.trim()).filter(Boolean);
  let t = 0;
  return lines.map(line => {
    const words    = line.split(/\s+/).filter(Boolean).length;
    const duration = Math.max(words * secsPerWord, 1.5);
    const seg      = { text: sanitizeLine(line), start: +t.toFixed(2), end: +(t + duration).toFixed(2) };
    t += duration;
    return seg;
  });
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
export async function mergeReel(reelId, clipPaths, audioPath, script, options = {}) {
  const { captionStyle = 'bold-stroke', effects = {}, musicPath = null } = options;
  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);

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
      ? `[vcat]scale=1116:1996,crop=1080:1920:x='18+18*sin(t*22)':y='18+18*sin(t*17)'[vshaken]`
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
        `x=(w-text_w)/2:y=h-180:line_spacing=8` +
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
          `x=(w-text_w)/2:y=h-180:line_spacing=8:` +
          `enable='between(t,${seg.start},${seg.end})'` +
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
        '-crf 23',
        '-preset fast',
        '-shortest',
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', (cmd) => console.log(`[FFmpeg] Starting reel ${reelId}:`, cmd))
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
