import path from 'path';
import fsp from 'fs/promises';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { generateTTS } from '../services/ttsService.js';
import {
  buildRevealClip,
  mergeSceneClips,
  getMediaDuration,
} from '../services/ffmpegService.js';
import { renderSceneFrames } from '../services/whiteboardRenderService.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Gemini client ─────────────────────────────────────────────────────────────
function getServiceAccountJSON() {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_B64) {
    try { return JSON.parse(Buffer.from(process.env.GOOGLE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')); } catch {}
  }
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    try { return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON); } catch {}
  }
  return null;
}

let _genai = null;
function getGenAI() {
  if (_genai) return _genai;
  const vertexApiKey = process.env.VERTEX_AI_API_KEY;
  if (vertexApiKey) {
    _genai = new GoogleGenAI({ vertexai: true, apiKey: vertexApiKey });
    return _genai;
  }
  const sa = getServiceAccountJSON();
  if (sa) {
    try {
      _genai = new GoogleGenAI({
        vertexai: true,
        project:  sa.project_id,
        location: 'us-central1',
        googleAuthOptions: {
          credentials: sa,
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      });
      return _genai;
    } catch (e) {
      console.error('[Whiteboard] Gemini service account init failed:', e.message);
    }
  }
  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (apiKey) _genai = new GoogleGenAI({ apiKey });
  return _genai;
}

// ── GET /whiteboard ───────────────────────────────────────────────────────────
export function getCreatePage(req, res) {
  res.render('whiteboard/create', { user: req.user });
}

// ── GET /whiteboard/loading/:id ───────────────────────────────────────────────
export async function getLoadingPage(req, res, db) {
  try {
    const id = parseInt(req.params.id);
    const { rows } = await db.query(
      'SELECT id, topic, status FROM whiteboard_projects WHERE id=? AND user_id=?',
      [id, req.user.id]
    );
    if (!rows.length) return res.redirect('/whiteboard');
    if (rows[0].status === 'completed') return res.redirect(`/whiteboard/result/${id}`);
    res.render('whiteboard/loading', { user: req.user, project: rows[0] });
  } catch (err) {
    console.error('[Whiteboard] getLoadingPage error:', err);
    res.redirect('/whiteboard');
  }
}

// ── GET /whiteboard/result/:id ────────────────────────────────────────────────
export async function getResultPage(req, res, db) {
  try {
    const id = parseInt(req.params.id);
    const { rows } = await db.query(
      'SELECT * FROM whiteboard_projects WHERE id=? AND user_id=?',
      [id, req.user.id]
    );
    if (!rows.length) return res.redirect('/whiteboard');
    const project = rows[0];
    if (project.status !== 'completed') return res.redirect(`/whiteboard/loading/${id}`);
    res.render('whiteboard/result', { user: req.user, project });
  } catch (err) {
    console.error('[Whiteboard] getResultPage error:', err);
    res.redirect('/whiteboard');
  }
}

// ── POST /whiteboard/generate ─────────────────────────────────────────────────
export async function generateWhiteboard(req, res, db) {
  try {
    const topic = (req.body.topic || '').trim();
    const title = (req.body.title || '').trim();
    const voice = req.body.voice || 'alloy';

    if (!topic) return res.status(400).json({ error: 'Topic is required' });
    if (topic.length < 5) return res.status(400).json({ error: 'Topic is too short' });
    if (topic.length > 500) return res.status(400).json({ error: 'Topic too long (max 500 chars)' });

    const result = await db.query(
      'INSERT INTO whiteboard_projects (user_id, topic, title, voice, status) VALUES (?,?,?,?,?)',
      [req.user.id, topic, title || null, voice, 'processing']
    );
    const projectId = result.insertId;

    res.json({ ok: true, projectId });

    setImmediate(() => runPipeline({ projectId, topic, title, voice, db }));
  } catch (err) {
    console.error('[Whiteboard] generateWhiteboard error:', err);
    res.status(500).json({ error: 'Failed to start generation' });
  }
}

// ── GET /whiteboard/:id/status ────────────────────────────────────────────────
export async function getStatus(req, res, db) {
  try {
    const id = parseInt(req.params.id);
    const { rows } = await db.query(
      'SELECT status, title, video_url, error_message FROM whiteboard_projects WHERE id=? AND user_id=?',
      [id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ── AI Script Generation ──────────────────────────────────────────────────────
async function generateAIScript(topic, customTitle) {
  const prompt = `You are creating an animated whiteboard video script about: "${topic}".

Return ONLY valid JSON (no markdown, no code fences, no explanation):
{
  "title": "Short engaging title (5-8 words)",
  "scenes": [
    {
      "title": "Scene heading (4-7 words)",
      "narration": "2-3 sentences the narrator reads aloud. Conversational and engaging.",
      "accent": "#FFD700",
      "elements": [
        { "type": "bullet", "content": "Key point text" },
        { "type": "highlight", "content": "Important callout text", "color": "#FFD700" },
        { "type": "text", "content": "Supporting explanation sentence" },
        { "type": "equation", "content": "Formula or expression" },
        { "type": "comparison", "col1_header": "Option A", "col2_header": "Option B",
          "rows": [{ "label": "Cost", "col1": "Low", "col2": "High" }] }
      ]
    }
  ]
}

Rules:
- 5-7 scenes total
- accent: pick one per scene from ["#FFD700", "#FF6B6B", "#4ECDC4", "#7C3AED", "#FF9F43"] — vary across scenes, no two consecutive scenes the same
- 2-3 elements per scene (use at most 1 comparison element per scene; if used, add 1 other element max)
- Use "comparison" when directly comparing two options/approaches/plans
- Use "highlight" for the single most important takeaway in a scene
- Use "bullet" for lists of quick facts
- Use "equation" only for math, formulas, or symbolic expressions
- Narration: conversational 2-3 sentences, read aloud by narrator
${customTitle ? `- Override the title field with: "${customTitle}"` : ''}`;

  const genai = getGenAI();
  if (!genai) throw new Error('Gemini AI is not configured. Set GEMINI_API_KEY or GOOGLE_SERVICE_ACCOUNT_JSON.');

  const response = await genai.models.generateContent({
    model:    'gemini-2.5-flash',
    contents: prompt,
    config:   { temperature: 0.85, maxOutputTokens: 6000, thinkingConfig: { thinkingBudget: 0 } },
  });

  const text  = response.text || '';
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('Gemini returned invalid JSON:\n' + text.slice(0, 300));
  return JSON.parse(match[0]);
}

// ── Background Pipeline ───────────────────────────────────────────────────────
async function runPipeline({ projectId, topic, title, voice, db }) {
  const tempDir    = path.join(process.cwd(), 'public', 'videos', 'temp', `wb-${projectId}`);
  const outputPath = path.join(process.cwd(), 'public', 'videos', `wb-${projectId}.mp4`);
  const clipPaths  = [];
  const audioPaths = [];

  const updateStatus = (status, extra = {}) =>
    db.query(
      'UPDATE whiteboard_projects SET status=?' +
        (extra.title      ? ',title=?'         : '') +
        (extra.scenesJson ? ',scenes_json=?'   : '') +
        (extra.videoUrl   ? ',video_url=?'     : '') +
        (extra.error      ? ',error_message=?' : '') +
        ' WHERE id=?',
      [
        status,
        ...(extra.title      ? [extra.title]      : []),
        ...(extra.scenesJson ? [extra.scenesJson]  : []),
        ...(extra.videoUrl   ? [extra.videoUrl]    : []),
        ...(extra.error      ? [extra.error]       : []),
        projectId,
      ]
    ).catch(e => console.error('[Whiteboard] DB update failed:', e.message));

  try {
    await fsp.mkdir(tempDir, { recursive: true });

    // ── Stage 1: AI Script ────────────────────────────────────────────────────
    console.log(`[Whiteboard] #${projectId} — Generating AI script for: "${topic}"`);
    await updateStatus('generating');
    const { title: aiTitle, scenes } = await generateAIScript(topic, title);
    const finalTitle = title || aiTitle;
    await updateStatus('rendering', { title: finalTitle, scenesJson: JSON.stringify(scenes) });

    // TTS provider
    let ttsProvider = 'openai';
    try {
      const { rows } = await db.query("SELECT value FROM admin_settings WHERE `key`='tts_provider'");
      ttsProvider = rows[0]?.value || 'openai';
    } catch {}

    console.log(`[Whiteboard] #${projectId} — "${finalTitle}" — ${scenes.length} scenes, tts=${ttsProvider}, voice=${voice}`);

    // ── Stages 2–6: per scene ─────────────────────────────────────────────────
    for (let i = 0; i < scenes.length; i++) {
      const scene = scenes[i];
      console.log(`[Whiteboard] #${projectId} — Scene ${i + 1}/${scenes.length}: "${scene.title}" (${(scene.elements||[]).length} elements)`);

      // 2. Render progressive frames
      const framePaths = await renderSceneFrames(scene, i, scenes.length, tempDir);

      // 3. TTS narration
      const audioPath = await generateTTS(scene.narration, voice, `wb-${projectId}-${i}`, ttsProvider);
      audioPaths.push(audioPath);

      // 4. TTS duration
      const ttsSeconds = await getMediaDuration(audioPath);

      // 5. Timing: spread reveal frames, hold final with Ken Burns
      const n          = framePaths.length;
      const revealDur  = Math.min(0.4, ttsSeconds / (n + 1));
      const holdDur    = Math.max(1.0, ttsSeconds - revealDur * (n - 1));

      // 6. Build reveal clip (video only)
      const clipPath = path.join(tempDir, `clip-${i}.mp4`);
      await buildRevealClip(framePaths, revealDur, holdDur, clipPath);
      clipPaths.push(clipPath);

      // Clean up frames
      for (const fp of framePaths) await fsp.unlink(fp).catch(() => {});
    }

    // ── Stage 7: Merge clips + narration ─────────────────────────────────────
    console.log(`[Whiteboard] #${projectId} — Merging ${clipPaths.length} clips…`);
    await updateStatus('encoding');
    await mergeSceneClips(clipPaths, audioPaths, outputPath);

    // ── Stage 8: Cleanup + finish ─────────────────────────────────────────────
    for (const p of clipPaths)  await fsp.unlink(p).catch(() => {});
    for (const p of audioPaths) await fsp.unlink(p).catch(() => {});
    await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});

    const videoUrl = `/videos/wb-${projectId}.mp4`;
    await updateStatus('completed', { videoUrl });
    console.log(`[Whiteboard] #${projectId} — Done → ${videoUrl}`);

    setTimeout(() => fsp.unlink(outputPath).catch(() => {}), 60 * 60 * 1000);

  } catch (err) {
    console.error(`[Whiteboard] #${projectId} — FAILED:`, err.message);
    await updateStatus('failed', { error: err.message });
    for (const p of clipPaths)  await fsp.unlink(p).catch(() => {});
    for (const p of audioPaths) await fsp.unlink(p).catch(() => {});
    await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
