import ffmpeg from 'fluent-ffmpeg';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import path from 'path';

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

/**
 * Merge video clips + TTS audio into a single vertical MP4 reel.
 *
 * Pipeline:
 *   1. Scale each clip to 1080×1920 (portrait), pad/crop as needed
 *   2. Concatenate all clips
 *   3. Overlay TTS audio as primary audio track
 *   4. Burn subtitle text at bottom of frame
 *   5. Export with fast libx264 / aac encoding
 *
 * @param {number}   reelId    - used to name the output file
 * @param {string[]} clipPaths - local paths to downloaded video clips
 * @param {string}   audioPath - local path to TTS mp3
 * @param {string}   script    - used to generate subtitle overlay text
 * @returns {Promise<string>}   resolved output file path
 */
export async function mergeReel(reelId, clipPaths, audioPath, script) {
  const outputPath = path.resolve(`./public/videos/${reelId}.mp4`);

  // Sanitise subtitle text: take first ~100 chars, escape ffmpeg special chars
  const subtitleText = script
    .replace(/[\r\n]+/g, ' ')
    .substring(0, 100)
    .trim()
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\u2019")   // replace apostrophes with typographic variant
    .replace(/:/g, '\\:')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]');

  return new Promise((resolve, reject) => {
    const cmd = ffmpeg();

    // Add video clip inputs
    clipPaths.forEach((p) => cmd.input(p));

    // Add audio input
    cmd.input(audioPath);

    const n = clipPaths.length;

    // Build filter_complex:
    //   - Scale/crop each clip to 1080x1920
    //   - Concat all scaled clips
    //   - Draw subtitle text near bottom
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

    const filterComplex = [
      ...scaleFilters,
      `${concatInputLabels}concat=n=${n}:v=1:a=0[vcat]`,
      `[vcat]drawtext=` +
        `text='${subtitleText}':` +
        `fontsize=40:` +
        `fontcolor=white:` +
        `borderw=3:` +
        `bordercolor=black:` +
        `x=(w-text_w)/2:` +
        `y=h-180:` +
        `line_spacing=8` +
        `[vout]`,
    ].join(';');

    cmd
      .complexFilter(filterComplex)
      .outputOptions([
        '-map [vout]',
        `-map ${n}:a`,        // audio from TTS input (index = n)
        '-c:v libx264',
        '-c:a aac',
        '-b:a 128k',
        '-crf 23',
        '-preset fast',
        '-shortest',          // trim to shorter of video/audio
        '-movflags +faststart',
        '-pix_fmt yuv420p',   // broad compatibility
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
