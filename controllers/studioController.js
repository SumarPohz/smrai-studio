import path from 'path';
import fs   from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── GET /studio ───────────────────────────────────────────────────────────────
export async function getEditor(req, res, db) {
  try {
    const { rows: projects } = await db.query(
      'SELECT id, name, updated_at FROM studio_projects WHERE user_id=? ORDER BY updated_at DESC LIMIT 20',
      [req.user.id]
    );
    const { rows: musicRows } = await db.query(
      'SELECT id FROM reels_music_presets WHERE full_audio IS NOT NULL ORDER BY created_at'
    );
    res.render('studio/editor', {
      user:      req.user,
      projects,
      musicList: musicRows.map(r => r.id),
    });
  } catch (err) {
    console.error('[studio] getEditor:', err);
    res.status(500).send('Error loading Studio');
  }
}

// ── GET /studio/list ──────────────────────────────────────────────────────────
export async function apiList(req, res, db) {
  try {
    const { rows } = await db.query(
      'SELECT id, name, total_duration, updated_at FROM studio_projects WHERE user_id=? ORDER BY updated_at DESC LIMIT 30',
      [req.user.id]
    );
    res.json({ ok: true, projects: rows });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
}

// ── POST /studio/save ─────────────────────────────────────────────────────────
export async function apiSave(req, res, db) {
  try {
    const { id, name, layers, totalDuration } = req.body;
    const userId = req.user.id;
    // Strip runtime-only fields (DOM elements) before storing
    const cleanLayers = (layers || []).map(l => {
      const { bgEl, audioEl, audioBuffer, ...rest } = l;
      return rest;
    });
    const layersJson = JSON.stringify(cleanLayers);

    if (id) {
      await db.query(
        'UPDATE studio_projects SET name=?, layers=?, total_duration=? WHERE id=? AND user_id=?',
        [name || 'Untitled', layersJson, totalDuration || 30, id, userId]
      );
      return res.json({ ok: true, id: parseInt(id) });
    }
    const result = await db.query(
      'INSERT INTO studio_projects (user_id, name, layers, total_duration) VALUES (?,?,?,?)',
      [userId, name || 'Untitled', layersJson, totalDuration || 30]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (err) {
    console.error('[studio] apiSave:', err);
    res.json({ ok: false, error: err.message });
  }
}

// ── DELETE /studio/:id ────────────────────────────────────────────────────────
export async function apiDelete(req, res, db) {
  try {
    await db.query(
      'DELETE FROM studio_projects WHERE id=? AND user_id=?',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
}

// ── POST /studio/upload-media ─────────────────────────────────────────────────
export async function apiUploadMedia(req, res) {
  try {
    if (!req.file) return res.json({ ok: false, error: 'No file uploaded' });
    const mime  = req.file.mimetype || '';
    const type  = mime.startsWith('video/') ? 'video'
                : mime.startsWith('audio/') ? 'audio'
                : 'image';
    res.json({ ok: true, url: `/uploads/${req.file.filename}`, type });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
}
