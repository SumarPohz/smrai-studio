import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import path from 'path';
import fs from 'fs/promises';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

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
function buildSubtitleSegments(script) {
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
  } = options;

  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });

  const grainFilter    = effects.filmGrain    ? ',noise=alls=20:allf=t' : '';
  const hasShake       = !!effects.shake;
  const hasAnimatedHook = !!effects.animatedHook;
  const hasBGM         = !!musicPath;
  const n              = clipPaths.length;
  // Hard cap: detect actual clip length from first clip name, fallback to 8s (Veo) or 10s
  const clipSec        = duration === '60-70' ? 12 : 8;
  const maxDuration    = n * clipSec;

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
    // Animated hook: 0.3s fade-in from black (pairs with 1.15× zoom-in on clip 0)
    const hookStage   = hasAnimatedHook
      ? `${afterShake}fade=t=in:st=0:d=0.3[vhooked]`
      : null;
    const afterHook   = hasAnimatedHook ? '[vhooked]' : afterShake;

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
