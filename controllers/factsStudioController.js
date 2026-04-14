import OpenAI from 'openai';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

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
