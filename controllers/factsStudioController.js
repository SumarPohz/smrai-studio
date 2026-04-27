import OpenAI from 'openai';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateTTS } from '../services/ttsService.js';
import { mergeFactsClips, mergeFactsClipsSync, getMediaDuration, generateSilentAudio } from '../services/ffmpegService.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let _openai = null;
function getOpenAI() {
  if (!_openai) _openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _openai;
}

// ── GET /facts-studio ─────────────────────────────────────────────────────────
export async function getEditor(req, res, db) {
  try {
    const { rows } = await db.query(
      `SELECT id, title, title_color, body, highlights, bg_type, bg_value, created_at
       FROM facts_studio WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.render('facts-studio/editor', {
      user:   req.user,
      drafts: rows,
    });
  } catch (err) {
    console.error('[factsStudio] getEditor error:', err);
    res.status(500).send('Error loading Facts Studio');
  }
}

// ── GET /facts-studio/list ────────────────────────────────────────────────────
export async function apiList(req, res, db) {
  try {
    const { rows } = await db.query(
      `SELECT id, title, title_color, body, highlights, bg_type, bg_value, created_at
       FROM facts_studio WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.json({ ok: true, drafts: rows });
  } catch (err) {
    console.error('[factsStudio] apiList error:', err);
    res.json({ ok: false, error: err.message });
  }
}

// ── POST /facts-studio/save ───────────────────────────────────────────────────
export async function apiSave(req, res, db) {
  try {
    const { id, title, title_color, body, highlights, bg_type, bg_value } = req.body;
    const userId = req.user.id;

    if (!body || !body.trim()) return res.json({ ok: false, error: 'Body text is required' });

    const highlightsJson = highlights ? JSON.stringify(highlights) : '[]';

    if (id) {
      // Update existing — verify ownership
      await db.query(
        `UPDATE facts_studio SET title=?, title_color=?, body=?, highlights=?, bg_type=?, bg_value=?, created_at=NOW()
         WHERE id=? AND user_id=?`,
        [title || 'DID YOU KNOW?', title_color || '#22c55e', body, highlightsJson, bg_type || 'color', bg_value || '#000000', id, userId]
      );
      return res.json({ ok: true, id: parseInt(id) });
    }

    const result = await db.query(
      `INSERT INTO facts_studio (user_id, title, title_color, body, highlights, bg_type, bg_value)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, title || 'DID YOU KNOW?', title_color || '#22c55e', body, highlightsJson, bg_type || 'color', bg_value || '#000000']
    );
    res.json({ ok: true, id: result.insertId });
  } catch (err) {
    console.error('[factsStudio] apiSave error:', err);
    res.json({ ok: false, error: err.message });
  }
}

// ── DELETE /facts-studio/:id ──────────────────────────────────────────────────
export async function apiDelete(req, res, db) {
  try {
    const id     = parseInt(req.params.id);
    const userId = req.user.id;

    // Fetch before delete to clean up bg file
    const { rows } = await db.query(
      'SELECT bg_type, bg_value FROM facts_studio WHERE id=? AND user_id=?',
      [id, userId]
    );
    if (!rows.length) return res.json({ ok: false, error: 'Not found' });

    const { bg_type, bg_value } = rows[0];
    await db.query('DELETE FROM facts_studio WHERE id=? AND user_id=?', [id, userId]);

    // Delete uploaded bg file if stored locally
    if ((bg_type === 'image' || bg_type === 'video') && bg_value && bg_value.startsWith('/uploads/')) {
      const filePath = path.join(__dirname, '..', 'public', bg_value);
      fs.unlink(filePath, () => {});
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[factsStudio] apiDelete error:', err);
    res.json({ ok: false, error: err.message });
  }
}

// ── POST /facts-studio/upload-bg ──────────────────────────────────────────────
export async function apiUploadBg(req, res) {
  try {
    if (!req.file) return res.json({ ok: false, error: 'No file uploaded' });
    const mime = req.file.mimetype || '';
    const type = mime.startsWith('video/') ? 'video' : 'image';
    const url  = `/uploads/${req.file.filename}`;
    res.json({ ok: true, type, url });
  } catch (err) {
    console.error('[factsStudio] apiUploadBg error:', err);
    res.json({ ok: false, error: err.message });
  }
}

// ── POST /facts-studio/ai-highlight ──────────────────────────────────────────
export async function apiAiHighlight(req, res) {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.json({ ok: false, error: 'No text provided' });

    const response = await getOpenAI().chat.completions.create({
      model: 'gpt-4.1-nano',
      messages: [
        {
          role: 'system',
          content: `You are a viral-content keyword highlighter. Given a fact or statement, identify up to 6 of the most impactful, surprising, or important words/short phrases. Return ONLY valid JSON — an array of objects with "word" and "color".
Use ONLY these colors: "#ef4444" (red — shocking/alarming), "#22c55e" (green — positive/key fact), "#f59e0b" (amber — numbers/stats), "#f9a8d4" (pink — superlatives/records), "#67e8f9" (cyan — technical terms).
Example: [{"word":"145 km/h","color":"#f59e0b"},{"word":"sinks into it","color":"#ef4444"}]`,
        },
        { role: 'user', content: text.trim() },
      ],
      temperature: 0.3,
      max_tokens: 200,
    });

    const raw = response.choices[0]?.message?.content?.trim() || '[]';
    // Strip markdown fences if present
    const clean = raw.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
    const highlights = JSON.parse(clean);
    res.json({ ok: true, highlights });
  } catch (err) {
    console.error('[factsStudio] aiHighlight error:', err);
    res.json({ ok: false, error: 'AI highlight failed' });
  }
}

// ── In-memory job status store (process-scoped, good enough for single-server) ─
const mergeJobs = new Map(); // jobId → { status, url, error }

// ── POST /facts-studio/merge-clips ───────────────────────────────────────────
export async function mergeClips(req, res, db) {
  const clipFiles = req.files?.['clips'] || [];
  const musicFile = req.files?.['music']?.[0] || null;
  const bodies    = JSON.parse(req.body?.bodies || '[]');
  const voice     = req.body?.voice || 'alloy';
  const doTTS     = req.body?.tts === '1';

  if (!clipFiles.length) return res.status(400).json({ error: 'No clips uploaded' });

  const jobId = `fsc-${req.user.id}-${Date.now()}`;
  mergeJobs.set(jobId, { status: 'processing', url: null, error: null });
  res.json({ jobId });

  setImmediate(() => runFactsMergePipeline({
    jobId, clipFiles, bodies, voice, doTTS, musicFile, userId: req.user.id, db,
  }));
}

// ── GET /facts-studio/merge-status/:jobId ────────────────────────────────────
export async function mergeStatus(req, res) {
  const job = mergeJobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
}

async function runFactsMergePipeline({ jobId, clipFiles, bodies, voice, doTTS, musicFile, userId, db }) {
  const tempDir    = path.join(process.cwd(), 'public', 'videos', 'temp');
  const outputPath = path.join(process.cwd(), 'public', 'videos', `facts-${jobId}.mp4`);
  const clipPaths  = clipFiles.map(f => f.path);
  const perClipAudioPaths = [];

  try {
    await fsp.mkdir(tempDir, { recursive: true });

    if (doTTS && bodies.length) {
      let ttsProvider = 'openai';
      try {
        const { rows } = await db.query("SELECT value FROM admin_settings WHERE `key` = 'tts_provider'");
        ttsProvider = rows[0]?.value || 'openai';
      } catch {}

      console.log(`[FactsMerge] #${jobId} — Per-clip TTS (${ttsProvider}, voice=${voice}) for ${bodies.length} clips…`);

      // Generate TTS separately for each clip's body text
      for (let i = 0; i < clipPaths.length; i++) {
        const body = (bodies[i] || '').trim();
        if (!body) {
          perClipAudioPaths.push(null); // will be replaced with silence
          continue;
        }
        const ap = await generateTTS(body, voice, `${jobId}-clip${i}`, ttsProvider);
        perClipAudioPaths.push(ap);
      }

      // Determine each clip's playback duration from its TTS audio (or recorded clip if silent)
      const clipDurations = await Promise.all(
        clipPaths.map(async (clipPath, i) => {
          if (perClipAudioPaths[i]) return await getMediaDuration(perClipAudioPaths[i]);
          return await getMediaDuration(clipPath);
        })
      );

      // Replace null entries (empty body) with a generated silent audio
      const finalAudioPaths = await Promise.all(
        perClipAudioPaths.map(async (ap, i) => {
          if (ap) return ap;
          const silentPath = path.join(tempDir, `${jobId}-silent${i}.mp3`);
          await generateSilentAudio(clipDurations[i], silentPath);
          return silentPath;
        })
      );

      const musicPath = musicFile ? musicFile.path : null;
      console.log(`[FactsMerge] #${jobId} — Merging ${clipPaths.length} clips with per-clip sync, durations: [${clipDurations.map(d => d.toFixed(1)).join(', ')}]s…`);
      await mergeFactsClipsSync(clipPaths, finalAudioPaths, clipDurations, outputPath, musicPath);

      for (const p of clipPaths)        await fsp.unlink(p).catch(() => {});
      for (const p of finalAudioPaths)  await fsp.unlink(p).catch(() => {});
      if (musicFile) await fsp.unlink(musicFile.path).catch(() => {});

    } else {
      // No TTS — music-only or silent merge
      const audioPath = musicFile ? musicFile.path : null;
      console.log(`[FactsMerge] #${jobId} — Merging ${clipPaths.length} clips (no TTS)…`);
      await mergeFactsClips(clipPaths, audioPath, outputPath);

      for (const p of clipPaths) await fsp.unlink(p).catch(() => {});
      if (musicFile) await fsp.unlink(musicFile.path).catch(() => {});
    }

    const url = `/videos/facts-${jobId}.mp4`;
    mergeJobs.set(jobId, { status: 'done', url, error: null });
    console.log(`[FactsMerge] #${jobId} — Done → ${url}`);

    setTimeout(() => fsp.unlink(outputPath).catch(() => {}), 15 * 60 * 1000);
  } catch (err) {
    console.error(`[FactsMerge] #${jobId} — failed:`, err.message);
    mergeJobs.set(jobId, { status: 'failed', url: null, error: err.message });
    for (const p of clipPaths)         await fsp.unlink(p).catch(() => {});
    for (const p of perClipAudioPaths) if (p) await fsp.unlink(p).catch(() => {});
    if (musicFile) await fsp.unlink(musicFile.path).catch(() => {});
  }
}
