import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import ffprobeInstaller from '@ffprobe-installer/ffprobe';
import path from 'path';
import fs from 'fs/promises';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);
ffmpeg.setFfprobePath(ffprobeInstaller.path);

// ── Caption style drawtext configurations ─────────────────────────────────────
const CAPTION_STYLES = {
  'bold-stroke':   'fontsize=76:fontcolor=white:borderw=5:bordercolor=black',
  'red-highlight': 'fontsize=70:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=red@0.85:boxborderw=12',
  'sleek':         'fontsize=58:fontcolor=white:borderw=2:bordercolor=black@0.5',
  'majestic':      'fontsize=78:fontcolor=gold:borderw=4:bordercolor=black',
  'beast':         'fontsize=84:fontcolor=yellow:borderw=6:bordercolor=black',
  'elegant':       'fontsize=64:fontcolor=white:borderw=2:bordercolor=black@0.6',
  'clarity':       'fontsize=68:fontcolor=white:borderw=2:bordercolor=black:box=1:boxcolor=black@0.5:boxborderw=10',
  'karaoke':       'fontsize=76:fontcolor=white:borderw=0:box=1:boxcolor=0x7c3aed@0.92:boxborderw=14',
};

// ── Highlight box color per caption style (word-by-word highlight) ────────────
const HIGHLIGHT_BOX = {
  'bold-stroke':   '0xFFD700',  // yellow
  'red-highlight': '0xdc2626',  // red
  'sleek':         '0x3b82f6',  // blue
  'majestic':      '0xb45309',  // amber
  'beast':         '0xca8a04',  // gold
  'elegant':       '0x7c3aed',  // purple
  'clarity':       '0x0ea5e9',  // sky blue
  'karaoke':       '0x7c3aed',  // purple
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

// ── Build timed subtitle segments — one word per segment ─────────────────────
// Each word gets its own segment for word-by-word highlight effect.
// Dramatic/emotional words hold 35% longer. Sentence-end punctuation adds a
// 0.25s pause so the screen briefly clears, mimicking natural speech rhythm.
export function buildSubtitleSegments(script) {
  const BASE_SPW = 60 / 175;  // ~0.343s per word — matches Google Neural2 TTS pace
  const DRAMATIC = /^(but|wait|listen|however|because|love|truth|real|change|life|time|never|always|every|only|just|now|stop|think|feel|remember|imagine|believe|know|understand|people|world|story|dream|fear|hope|fail|win|lose|moment|chance|choice|power|mind|heart|soul|pain|joy|wrong|right|end|start|begin|yet|still|already)$/i;

  const segments = [];
  let t = 0;

  script.split(/\n+/).map(l => l.trim()).filter(Boolean).forEach(line => {
    line.split(/\s+/).filter(Boolean).forEach(w => {
      const bare  = w.replace(/[.,!?;:'"]/g, '');
      const dur   = DRAMATIC.test(bare) ? BASE_SPW * 1.1 : BASE_SPW;
      const pause = /[.!?]$/.test(w) ? 0.1 : 0;
      const GAP   = 0.03;

      segments.push({
        text:  sanitizeLine(w),
        start: +t.toFixed(2),
        end:   +(t + dur - GAP).toFixed(2),
      });
      t += dur + pause;
    });
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
 * Image is first scaled to a fixed 1296×2304 (20% oversize), then a 1080×1920
 * crop window is animated using t-based x/y expressions.
 * NOTE: scale filter does NOT support t/min()/max() in its expressions on all
 * platforms — only the crop filter's evaluator handles those safely.
 */
const PAN_VARIANTS = [
  // pan top→bottom
  { x: `(iw-ow)/2`,            y: `(ih-oh)*min(t/D,1)` },
  // pan bottom→top
  { x: `(iw-ow)/2`,            y: `(ih-oh)*max(1-t/D,0)` },
  // pan left→right
  { x: `(iw-ow)*min(t/D,1)`,   y: `(ih-oh)/2` },
  // pan right→left
  { x: `(iw-ow)*max(1-t/D,0)`, y: `(ih-oh)/2` },
  // diagonal top-left→bottom-right
  { x: `(iw-ow)*min(t/D,1)`,   y: `(ih-oh)*min(t/D,1)` },
  // diagonal bottom-right→top-left
  { x: `(iw-ow)*max(1-t/D,0)`, y: `(ih-oh)*max(1-t/D,0)` },
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
    captionStyle   = 'bold-stroke',
    effects        = {},
    musicPath      = null,
    duration       = '30-40',
    imageDurations = null,   // per-image script-synced durations in seconds
  } = options;

  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const captionParams = CAPTION_STYLES[captionStyle] || CAPTION_STYLES['bold-stroke'];
  const grainFilter   = effects.filmGrain ? ',noise=alls=20:allf=t' : '';
  const hasShake      = !!effects.shake;
  const hasZoom       = !!effects.smoothZoom;
  const hasBGM        = !!musicPath;

  // Word highlight params: white text on a colored box — one word at a time, CapCut style
  const fontsizeMatch   = captionParams.match(/fontsize=(\d+)/);
  const fontSize        = fontsizeMatch ? fontsizeMatch[1] : '64';
  const boxHex          = HIGHLIGHT_BOX[captionStyle] || '0xFFD700';
  const highlightParams = `fontsize=${fontSize}:fontcolor=white:borderw=3:bordercolor=black@0.6:box=1:boxcolor=${boxHex}@0.95:boxborderw=18`;

  // Use per-image script-synced durations; fall back to a fixed value
  const fallbackDur = duration === '60-70' ? 7 : 5;
  const durations   = imagePaths.map((_, i) =>
    (imageDurations && imageDurations[i]) ? imageDurations[i] : fallbackDur
  );

  const n = imagePaths.length;  // audio stream index = n, BGM = n+1

  const segments = buildSubtitleSegments(script);

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Each image: looped still-image stream at 24fps for its script-synced duration.
    // -framerate 24 sets the decode framerate so the filter graph gets a valid PTS timeline.
    imagePaths.forEach((p, i) => {
      cmd.input(p).inputOptions(['-loop 1', '-framerate 24', `-t ${durations[i]}`]);
    });
    cmd.input(audioPath);
    if (hasBGM) {
      cmd.input(musicPath);
      console.log(`[FFmpeg] BGM mixed: ${path.basename(musicPath)}`);
    }

    // Per-image: fit to 1080×1920, overscale 20% to 1296×2304 (static — scale filter
    // does not support t/min()/max() expressions), then animated crop for pan effect.
    const imageFilters = imagePaths.map((_, i) => {
      const pan = PAN_VARIANTS[i % PAN_VARIANTS.length];
      const px  = pan.x.replace(/D/g, durations[i]);
      const py  = pan.y.replace(/D/g, durations[i]);
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
    const afterShake  = hasShake ? '[vshaken]' : '[vcat]';
    const zoomStage   = hasZoom
      ? `${afterShake}scale=1134:2016,crop=1080:1920:x='27+27*sin(t*0.3)':y='48+48*sin(t*0.25)'[vzoom]`
      : null;
    const drawtextSrc = hasZoom ? '[vzoom]' : afterShake;

    // Timed subtitle filters (identical logic to mergeReel)
    let subtitleFilters;
    if (segments.length <= 1) {
      const fallbackText = sanitizeLine(
        script.replace(/[\r\n]+/g, ' ').substring(0, 100).trim()
      );
      subtitleFilters = [
        `${drawtextSrc}drawtext=` +
        `text='${fallbackText}':` +
        `${highlightParams}:` +
        `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1` +
        `${grainFilter}[vout]`,
      ];
    } else {
      subtitleFilters = segments.map((seg, i) => {
        const inputLabel  = i === 0 ? drawtextSrc : `[vsub${i - 1}]`;
        const isLast      = i === segments.length - 1;
        const outputLabel = isLast ? '[vout]' : `[vsub${i}]`;
        const grain       = isLast ? grainFilter : '';
        // Fast fade-in + slide up: word starts 30px lower and rises to final position over 0.12s
        const alphaExpr   = `min(1,max(0,(t-${seg.start})/0.04))`;
        const yExpr       = `h-250+30*max(0,1-(t-${seg.start})/0.12)`;
        return (
          `${inputLabel}drawtext=` +
          `text='${seg.text}':` +
          `${highlightParams}:` +
          `x=(w-text_w)/2:y='${yExpr}':line_spacing=8:fix_bounds=1:` +
          `enable='between(t,${seg.start},${seg.end})':` +
          `alpha='${alphaExpr}'` +
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
      ...(zoomStage       ? [zoomStage]        : []),
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
      .on('progress', () => {})
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

// ── Sentence-level caption segments ──────────────────────────────────────────
// Split script into sentences, time each one by word count at 150 WPM.
function buildSentenceSegments(script) {
  const WPM       = 150;
  const sentences = script
    .replace(/\n+/g, ' ')
    .split(/(?<=[.!?])\s+/)
    .map(s => sanitizeLine(s.trim()))
    .filter(Boolean);

  let t = 0;
  return sentences.map(s => {
    const words = s.split(/\s+/).filter(Boolean).length;
    const dur   = Math.max(+(words / WPM * 60).toFixed(2), 1.5);
    const seg   = { text: s, start: +t.toFixed(2), end: +(t + dur - 0.1).toFixed(2) };
    t += dur;
    return seg;
  });
}

// Auto caption style — fallback when Whisper words unavailable
const AUTO_CAPTION = 'fontsize=80:fontcolor=white:borderw=6:bordercolor=black';

// ── Karaoke ASS subtitle generation ──────────────────────────────────────────

function toAssTime(secs) {
  const h  = Math.floor(secs / 3600);
  const m  = Math.floor((secs % 3600) / 60);
  const s  = Math.floor(secs % 60);
  const cs = Math.round((secs % 1) * 100);
  return `${h}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}.${String(cs).padStart(2,'0')}`;
}

function sanitizeAssWord(w) {
  return w.replace(/\\/g, '\\\\').replace(/\{/g, '\\{').replace(/\}/g, '\\}');
}

function escapeSubtitlePath(p) {
  // FFmpeg subtitle filter needs colon escaped on Windows
  if (process.platform === 'win32') {
    return p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, '$1\\:');
  }
  return p;
}

/**
 * Build an ASS subtitle file for karaoke-style captions:
 * 3 words visible at a time, current word highlighted in yellow + bold.
 * Returns the file path (caller must delete after render).
 */
async function buildAssFile(words, reelId) {
  const CHUNK     = 3;
  const HIGHLIGHT = '&H0000FFFF&';  // yellow  (ASS = AABBGGRR)
  const WHITE     = '&H00FFFFFF&';
  const BLACK     = '&H00000000&';

  const header = [
    '[Script Info]',
    'ScriptType: v4.00+',
    'PlayResX: 1080',
    'PlayResY: 1920',
    'ScaledBorderAndShadow: yes',
    '',
    '[V4+ Styles]',
    'Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding',
    `Style: Default,Arial,78,${WHITE},${WHITE},${BLACK},${BLACK},1,0,0,0,100,100,0,0,1,5,0,2,30,30,400,1`,
    '',
    '[Events]',
    'Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text',
  ].join('\n');

  const events = [];
  for (let gi = 0; gi < words.length; gi += CHUNK) {
    const group = words.slice(gi, gi + CHUNK);
    for (let wi = 0; wi < group.length; wi++) {
      const w         = group[wi];
      const startTime = toAssTime(w.start);
      // End = next word start (or this word's own end for last in group)
      const nextWord  = group[wi + 1] || words[gi + wi + 1];
      const endTime   = toAssTime(nextWord ? nextWord.start : w.end);

      const text = group.map((gw, j) => {
        const clean = sanitizeAssWord(gw.word);
        return j === wi
          ? `{\\c${HIGHLIGHT}}${clean}{\\c${WHITE}}`
          : clean;
      }).join(' ');

      events.push(`Dialogue: 0,${startTime},${endTime},Default,,0,0,0,,${text}`);
    }
  }

  const assPath = path.resolve(`./public/videos/temp/${reelId}-captions.ass`);
  await fs.mkdir(path.dirname(assPath), { recursive: true });
  await fs.writeFile(assPath, [header, ...events].join('\n'), 'utf8');
  return assPath;
}

/**
 * Merge xAI-generated video clips + TTS audio into a single vertical MP4 reel.
 * No Ken Burns (clips already have motion). Big sentence-level captions auto-generated.
 *
 * @param {number}   reelId
 * @param {string[]} clipPaths      - local paths to downloaded mp4 clips
 * @param {string}   audioPath      - local path to TTS mp3
 * @param {string}   script         - full script for caption timing
 * @param {object}   options
 * @param {object}   [options.effects]
 * @param {string}   [options.musicPath=null]
 * @param {string}   [options.duration='30-40']
 * @returns {Promise<string>}  output file path
 */
export async function mergeReelFromVideos(reelId, clipPaths, audioPath, script, options = {}) {
  const {
    effects         = {},
    musicPath       = null,
    duration        = '30-40',
    captionSegments = null,
    captionWords    = null,
    videoSpeed      = 1.0,
    audioDuration   = null,
  } = options;

  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const grainFilter    = effects.filmGrain    ? ',noise=alls=20:allf=t' : '';
  const hasShake       = !!effects.shake;
  const hasZoom        = !!effects.smoothZoom;
  const hasAnimatedHook = !!effects.animatedHook;
  const hasBGM         = !!musicPath;
  const n              = clipPaths.length;
  // Use real audio duration when provided (media reels), otherwise estimate from clip count
  const clipSec        = duration === '60-70' ? 12 : 8;
  const maxDuration    = audioDuration ? Math.ceil(audioDuration) + 2 : n * clipSec;

  // Use Whisper-derived timestamps if available, otherwise fall back to WPM estimation
  const segments = captionSegments || buildSentenceSegments(script);

  // Build ASS karaoke file — prefer Whisper words, fall back to WPM word segments
  let assFilePath = null;
  const assWords = captionWords?.length
    ? captionWords
    : buildSubtitleSegments(script).map(s => ({ word: s.text, start: s.start, end: s.end }));
  if (assWords.length) {
    assFilePath = await buildAssFile(assWords, reelId);
    console.log(`[FFmpeg] ASS karaoke file ready: ${path.basename(assFilePath)} (${captionWords?.length ? 'Whisper' : 'WPM'})`);
  }

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Inputs: video clips → TTS audio → optional BGM
    clipPaths.forEach(p => cmd.input(p));
    cmd.input(audioPath);
    if (hasBGM) {
      cmd.input(musicPath);
      console.log(`[FFmpeg] BGM mixed: ${path.basename(musicPath)}`);
    }

    // Scale/crop each clip to 1080×1920 portrait.
    // Clip 0 gets a 15% zoom-in when animated hook is on — creates a dramatic opening frame.
    const scaleFilters = clipPaths.map((_, i) => {
      if (i === 0 && hasAnimatedHook) {
        // Overscale 15% then center-crop → 1.15× zoom punch on the hook clip
        return (
          `[0:v]` +
          `scale=1242:2208:force_original_aspect_ratio=increase,` +
          `crop=1080:1920:x='(iw-ow)/2':y='(ih-oh)/2',` +
          `setsar=1,fps=24[v0]`
        );
      }
      return (
        `[${i}:v]` +
        `scale=1080:1920:force_original_aspect_ratio=increase,` +
        `crop=1080:1920,setsar=1,fps=24` +
        `[v${i}]`
      );
    });

    // Concat clips — xfade requires FFmpeg 4.3+; concat works on all versions
    const concatLabels = clipPaths.map((_, i) => `[v${i}]`).join('');
    const xfadeFilters = n === 1
      ? [`[v0]copy[vcat]`]
      : [`${concatLabels}concat=n=${n}:v=1:a=0[vcat]`];

    const shakeStage  = hasShake
      ? `[vcat]scale=1116:1996,crop=1080:1920:x='18+18*sin(t*4)':y='18+18*sin(t*3)'[vshaken]`
      : null;
    const afterShake  = hasShake ? '[vshaken]' : '[vcat]';
    // Smooth zoom: 5% scale-up + slow sinusoidal crop → subtle breathe-zoom effect
    const zoomStage   = hasZoom
      ? `${afterShake}scale=1134:2016,crop=1080:1920:x='27+27*sin(t*0.3)':y='48+48*sin(t*0.25)'[vzoom]`
      : null;
    const afterZoom   = hasZoom ? '[vzoom]' : afterShake;
    // Animated hook: 0.3s fade-in from black (pairs with 1.15× zoom-in on clip 0)
    const hookStage   = hasAnimatedHook
      ? `${afterZoom}fade=t=in:st=0:d=0.3[vhooked]`
      : null;
    const afterHook   = hasAnimatedHook ? '[vhooked]' : afterZoom;

    // Video-only slow-motion: scale PTS without touching audio
    const ptsMult     = videoSpeed > 0 && videoSpeed !== 1.0 ? (1 / videoSpeed).toFixed(4) : null;
    const speedStage  = ptsMult ? `${afterHook}setpts=${ptsMult}*PTS[vspeed]` : null;
    const drawtextSrc = ptsMult ? '[vspeed]' : afterHook;

    // Karaoke ASS captions (Whisper word timestamps) — or sentence drawtext fallback
    let subtitleFilters;
    if (assFilePath) {
      // 3-word karaoke groups, current word highlighted yellow — single subtitles filter
      const escapedAssPath = escapeSubtitlePath(assFilePath);
      subtitleFilters = [
        `${drawtextSrc}subtitles='${escapedAssPath}'${grainFilter}[vout]`,
      ];
    } else if (segments.length <= 1) {
      const fallback = sanitizeLine(script.replace(/[\r\n]+/g, ' ').substring(0, 100).trim());
      subtitleFilters = [
        `${drawtextSrc}drawtext=text='${fallback}':${AUTO_CAPTION}:` +
        `x=(w-text_w)/2:y=h-220:line_spacing=8:fix_bounds=1` +
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
          `text='${seg.text}':${AUTO_CAPTION}:` +
          `x=(w-text_w)/2:y=h-220:line_spacing=8:fix_bounds=1:` +
          `enable='between(t,${seg.start},${seg.end})'` +
          `${grain}${outputLabel}`
        );
      });
    }

    const audioFilterPart = hasBGM
      ? `[${n}:a]volume=1.0[tts];[${n + 1}:a]volume=0.15[bgm];[tts][bgm]amix=inputs=2:duration=first[aout]`
      : null;

    const filterComplex = [
      ...scaleFilters,
      ...xfadeFilters,
      ...(shakeStage      ? [shakeStage]      : []),
      ...(zoomStage       ? [zoomStage]        : []),
      ...(hookStage       ? [hookStage]        : []),
      ...(speedStage      ? [speedStage]       : []),
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
        `-t ${maxDuration}`,
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', () => console.log(`[FFmpeg] Starting video reel #${reelId} (max ${maxDuration}s)`))
      .on('progress', () => {})
      .on('end', () => {
        if (assFilePath) fs.unlink(assFilePath).catch(() => {});
        console.log(`[FFmpeg] Reel #${reelId} complete → ${outputPath}`);
        resolve(outputPath);
      })
      .on('error', (err, _stdout, stderr) => {
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
  const hasZoom       = !!effects.smoothZoom;
  const hasBGM        = !!musicPath;

  // Word highlight params: white text on a colored box — one word at a time, CapCut style
  const fontsizeMatch   = captionParams.match(/fontsize=(\d+)/);
  const fontSize        = fontsizeMatch ? fontsizeMatch[1] : '64';
  const boxHex          = HIGHLIGHT_BOX[captionStyle] || '0xFFD700';
  const highlightParams = `fontsize=${fontSize}:fontcolor=white:borderw=3:bordercolor=black@0.6:box=1:boxcolor=${boxHex}@0.95:boxborderw=18`;

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
    const afterShake  = hasShake ? '[vshaken]' : '[vcat]';
    const zoomStage   = hasZoom
      ? `${afterShake}scale=1134:2016,crop=1080:1920:x='27+27*sin(t*0.3)':y='48+48*sin(t*0.25)'[vzoom]`
      : null;
    const drawtextSrc = hasZoom ? '[vzoom]' : afterShake;

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
        `${highlightParams}:` +
        `x=(w-text_w)/2:y=h-250:line_spacing=8:fix_bounds=1` +
        `${grainFilter}[vout]`,
      ];
    } else {
      subtitleFilters = segments.map((seg, i) => {
        const inputLabel  = i === 0 ? drawtextSrc : `[vsub${i - 1}]`;
        const isLast      = i === segments.length - 1;
        const outputLabel = isLast ? '[vout]' : `[vsub${i}]`;
        const grain       = isLast ? grainFilter : '';
        const alphaExpr   = `min(1,max(0,(t-${seg.start})/0.04))`;
        const yExpr       = `h-250+30*max(0,1-(t-${seg.start})/0.12)`;
        return (
          `${inputLabel}drawtext=` +
          `text='${seg.text}':` +
          `${highlightParams}:` +
          `x=(w-text_w)/2:y='${yExpr}':line_spacing=8:fix_bounds=1:` +
          `enable='between(t,${seg.start},${seg.end})':` +
          `alpha='${alphaExpr}'` +
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
      ...(zoomStage         ? [zoomStage]         : []),
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
      .on('progress', () => {})
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

/**
 * Get duration of an audio/video file in seconds.
 * @param {string} filePath
 * @returns {Promise<number>}
 */
export function getMediaDuration(filePath) {
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(filePath, (err, meta) => {
      if (err) return reject(err);
      resolve(meta?.format?.duration || 0);
    });
  });
}

/**
 * Convert a single image to a short video clip with animation effects.
 * Used by the Media Reel pipeline to turn uploaded images into video segments.
 *
 * @param {string} imagePath    - path to input image (jpg/png/webp)
 * @param {number} durationSec  - desired clip duration in seconds
 * @param {string} effect       - 'kenburns' | 'zoom' | 'shake' | 'none'
 * @param {string} outputPath   - path for the output .mp4 clip
 * @returns {Promise<string>}   outputPath
 */
export async function imageToVideoClip(imagePath, durationSec, effect, outputPath, isGif = false) {
  const fps = 24;
  const frames = Math.round(durationSec * fps);

  // Cover base: scale to fill 1080×1920 maintaining aspect ratio (no stretch, crops excess)
  const coverBase = `scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920`;
  // Zoom base: 20% larger than output — gives zoompan room to pan without hitting edges
  const zoomBase  = `scale=1296:2304:force_original_aspect_ratio=increase,crop=1296:2304`;

  let vfFilter;
  if (effect === 'kenburns') {
    vfFilter = `${zoomBase},zoompan=z='min(zoom+0.0015,1.15)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=${frames}:s=1080x1920:fps=${fps},setsar=1`;
  } else if (effect === 'zoom') {
    vfFilter = `${zoomBase},zoompan=z='min(zoom+0.002,1.2)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=${frames}:s=1080x1920:fps=${fps},setsar=1`;
  } else if (effect === 'shake') {
    vfFilter = `${coverBase},scale=1116:1996,crop=1080:1920:x='18+12*sin(n/12)':y='18+12*cos(n/15)',setsar=1,fps=${fps}`;
  } else {
    vfFilter = `${coverBase},setsar=1,fps=${fps}`;
  }

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg().input(imagePath);
    if (isGif) {
      // Animated GIF: loop continuously for the clip duration
      cmd.inputOptions(['-ignore_loop', '0']);
    } else {
      // Static image: loop the single frame
      cmd.inputOptions(['-loop', '1']);
    }
    cmd
      .duration(durationSec)
      .videoFilters(vfFilter)
      .videoCodec('libx264')
      .outputOptions(['-pix_fmt', 'yuv420p', '-preset', 'ultrafast', '-crf', '26', '-an'])
      .output(outputPath)
      .on('end', () => resolve(outputPath))
      .on('error', (err) => reject(new Error(`imageToVideoClip failed: ${err.message}`)))
      .run();
  });
}

/**
 * Merge multiple WebM browser-recorded clips into a single 1080×1920 MP4 (YouTube Shorts).
 * Optionally mixes in an audio track (TTS narration or background music).
 *
 * @param {string[]} clipPaths  - array of WebM file paths on disk
 * @param {string|null} audioPath - optional audio file path (mp3/wav/aac)
 * @param {string} outputPath   - destination MP4 path
 */
export async function mergeFactsClips(clipPaths, audioPath, outputPath) {
  if (!clipPaths.length) throw new Error('mergeFactsClips: no clips provided');
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const n = clipPaths.length;

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();
    clipPaths.forEach(p => cmd.input(p));
    if (audioPath) cmd.input(audioPath).inputOptions(['-stream_loop', '-1']);

    // Scale/crop each clip to 1080×1920 portrait
    const scaleFilters = clipPaths.map((_, i) =>
      `[${i}:v]scale=1080:1920:force_original_aspect_ratio=increase,` +
      `crop=1080:1920,setsar=1,fps=30[v${i}]`
    );
    const concatLabels = clipPaths.map((_, i) => `[v${i}]`).join('');
    const concatFilter = n === 1
      ? `[v0]copy[vout]`
      : `${concatLabels}concat=n=${n}:v=1:a=0[vout]`;

    const filterComplex = [...scaleFilters, concatFilter].join(';');

    cmd
      .complexFilter(filterComplex)
      .outputOptions([
        '-map [vout]',
        audioPath ? `-map ${n}:a` : '-an',
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
      .on('start', cmd => console.log(`[FactsMerge] FFmpeg start: ${cmd}`))
      .on('end', () => { console.log(`[FactsMerge] Done → ${outputPath}`); resolve(outputPath); })
      .on('error', (err, _stdout, stderr) => {
        console.error('[FactsMerge] FFmpeg error:', stderr || err.message);
        reject(new Error(stderr || err.message));
      })
      .run();
  });
}

/**
 * Generate a silent MP3 of the given duration (for clips with no body text).
 */
export function generateSilentAudio(durationSec, outputPath) {
  return new Promise((resolve, reject) => {
    ffmpeg()
      .input('anullsrc=r=44100:cl=stereo')
      .inputOptions(['-f', 'lavfi'])
      .duration(durationSec)
      .audioCodec('libmp3lame')
      .audioBitrate('128k')
      .output(outputPath)
      .on('end', resolve)
      .on('error', reject)
      .run();
  });
}

/**
 * Merge WebM clips into 1080×1920 MP4 with per-clip TTS audio sync.
 * Each clip video loops to match its TTS audio duration.
 * Optional background music is mixed underneath at 40% volume.
 *
 * @param {string[]} clipPaths     - WebM files (one per fact card)
 * @param {string[]} audioPaths    - MP3 TTS files, parallel to clipPaths
 * @param {number[]} clipDurations - Seconds each clip should run (matches TTS duration)
 * @param {string}   outputPath    - Destination MP4
 * @param {string|null} musicPath  - Optional background music (loops if short)
 */
export async function mergeFactsClipsSync(clipPaths, audioPaths, clipDurations, outputPath, musicPath = null) {
  if (!clipPaths.length) throw new Error('mergeFactsClipsSync: no clips provided');
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const n = clipPaths.length;

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Video inputs — no special input flags needed; tpad handles extension in filter
    clipPaths.forEach(p => cmd.input(p));

    // Per-clip TTS audio inputs
    audioPaths.forEach(p => cmd.input(p));

    // Background music input — must call input() THEN inputOptions() for correct order
    if (musicPath) cmd.input(musicPath).inputOptions(['-stream_loop', '-1']);

    const musicIdx = n * 2;

    // Scale + crop each video, then tpad to freeze last frame until TTS duration is reached
    const vFilters = clipPaths.map((_, i) => {
      const d = clipDurations[i].toFixed(3);
      return `[${i}:v]scale=1080:1920:force_original_aspect_ratio=increase,` +
             `crop=1080:1920,setsar=1,fps=30,` +
             `tpad=stop=-1:stop_mode=clone,trim=duration=${d},setpts=PTS-STARTPTS[v${i}]`;
    });

    // Trim each TTS audio to its duration
    const aFilters = audioPaths.map((_, i) => {
      const d = clipDurations[i].toFixed(3);
      return `[${n + i}:a]atrim=duration=${d},asetpts=PTS-STARTPTS[a${i}]`;
    });

    // Concat video segments
    const vLabels = clipPaths.map((_, i) => `[v${i}]`).join('');
    const concatV = n === 1 ? `[v0]copy[vout]` : `${vLabels}concat=n=${n}:v=1:a=0[vout]`;

    // Concat audio segments
    const aLabels = audioPaths.map((_, i) => `[a${i}]`).join('');
    const concatA = n === 1 ? `[a0]acopy[narration]` : `${aLabels}concat=n=${n}:v=0:a=1[narration]`;

    const filters = [...vFilters, ...aFilters, concatV, concatA];

    let audioMap;
    if (musicPath) {
      // aloop keeps music running until narration ends; amix blends at 40% volume
      filters.push(
        `[${musicIdx}:a]aloop=loop=-1:size=2000000000[musicloop]`,
        `[narration][musicloop]amix=inputs=2:duration=first:weights=1 0.4[aout]`
      );
      audioMap = '[aout]';
    } else {
      audioMap = '[narration]';
    }

    cmd
      .complexFilter(filters.join(';'))
      .outputOptions([
        '-map [vout]',
        `-map ${audioMap}`,
        '-c:v libx264',
        '-c:a aac',
        '-b:a 128k',
        '-crf 26',
        '-preset ultrafast',
        '-r 30',
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', c => console.log(`[FactsMergeSync] FFmpeg start: ${c}`))
      .on('end', () => { console.log(`[FactsMergeSync] Done → ${outputPath}`); resolve(outputPath); })
      .on('error', (err, _stdout, stderr) => {
        console.error('[FactsMergeSync] FFmpeg error:', stderr || err.message);
        reject(new Error(stderr || err.message));
      })
      .run();
  });
}

/**
 * Concatenate pre-built scene clips (already correct duration) with per-clip
 * audio tracks into a single 1080×1920 MP4. Optionally mixes background music
 * underneath the narration at 15% volume.
 *
 * @param {string[]} clipPaths   - MP4 clips (one per scene, already correct duration)
 * @param {string[]} audioPaths  - MP3 narration files parallel to clipPaths
 * @param {string}   outputPath  - destination MP4
 * @param {string|null} musicPath - optional background music (looped)
 */
export async function mergeSceneClips(clipPaths, audioPaths, outputPath, musicPath = null) {
  if (!clipPaths.length) throw new Error('mergeSceneClips: no clips provided');
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const n = clipPaths.length;

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    clipPaths.forEach(p  => cmd.input(p));
    audioPaths.forEach(p => cmd.input(p));
    if (musicPath) cmd.input(musicPath).inputOptions(['-stream_loop', '-1']);

    const musicIdx = n * 2;

    const vLabels = clipPaths.map((_, i) => `[${i}:v]`).join('');
    const concatV  = n === 1
      ? `[0:v]copy[vout]`
      : `${vLabels}concat=n=${n}:v=1:a=0[vout]`;

    const aLabels = audioPaths.map((_, i) => `[${n + i}:a]`).join('');
    const concatA  = n === 1
      ? `[${n}:a]acopy[narration]`
      : `${aLabels}concat=n=${n}:v=0:a=1[narration]`;

    const filters = [concatV, concatA];
    let audioMap;

    if (musicPath) {
      filters.push(`[${musicIdx}:a]aloop=loop=-1:size=2000000000[ml]`);
      filters.push(`[narration][ml]amix=inputs=2:duration=first:weights=1 0.15[aout]`);
      audioMap = '[aout]';
    } else {
      audioMap = '[narration]';
    }

    cmd
      .complexFilter(filters.join(';'))
      .outputOptions([
        '-map [vout]',
        `-map ${audioMap}`,
        '-c:v libx264',
        '-c:a aac',
        '-b:a 128k',
        '-crf 24',
        '-preset fast',
        '-r 30',
        '-movflags +faststart',
        '-pix_fmt yuv420p',
      ])
      .output(outputPath)
      .on('start', c  => console.log(`[SceneMerge] FFmpeg start: ${c}`))
      .on('end',   () => { console.log(`[SceneMerge] Done → ${outputPath}`); resolve(outputPath); })
      .on('error', (err, _stdout, stderr) => {
        console.error('[SceneMerge] FFmpeg error:', stderr || err.message);
        reject(new Error(stderr || err.message));
      })
      .run();
  });
}

/**
 * Build one animated scene clip from progressive reveal PNGs.
 * Each reveal frame (all but last) is shown statically for revealDur seconds.
 * The final frame plays with Ken Burns zoom for holdDur seconds.
 *
 * @param {string[]} framePaths - PNG files: [titleFrame, ...elementFrames]
 * @param {number}   revealDur  - seconds each reveal frame is shown
 * @param {number}   holdDur    - seconds final frame plays with Ken Burns
 * @param {string}   outputPath - destination MP4 (video only, no audio)
 */
export async function buildRevealClip(framePaths, revealDur, holdDur, outputPath) {
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  const n   = framePaths.length;
  const fps = 30;

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Each frame as a looping still image for its duration
    framePaths.forEach((p, i) => {
      const dur = i < n - 1 ? revealDur : holdDur;
      cmd.input(p).inputOptions(['-loop', '1', '-t', String(dur)]);
    });

    // Scale every frame to 1080×1920 at 30fps (static — no zoompan)
    const scaleFilters = framePaths.map((_, i) =>
      `[${i}:v]scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920,setsar=1,fps=${fps}[f${i}]`
    );

    const labels        = framePaths.map((_, i) => `[f${i}]`).join('');
    const concatFilter  = n === 1
      ? `[f0]copy[vout]`
      : `${labels}concat=n=${n}:v=1:a=0[vout]`;

    const filterComplex = [...scaleFilters, concatFilter].join(';');

    cmd
      .complexFilter(filterComplex)
      .outputOptions([
        '-map [vout]',
        '-c:v libx264',
        '-pix_fmt yuv420p',
        '-preset fast',
        '-crf 23',
        '-an',
      ])
      .output(outputPath)
      .on('start', c  => console.log(`[RevealClip] FFmpeg start: ${c.slice(0, 120)}`))
      .on('end',   () => { console.log(`[RevealClip] Done → ${outputPath}`); resolve(outputPath); })
      .on('error', (err, _stdout, stderr) => {
        console.error('[RevealClip] FFmpeg error:', stderr || err.message);
        reject(new Error(stderr || err.message));
      })
      .run();
  });
}
