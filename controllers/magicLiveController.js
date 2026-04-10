import PDFDocument from 'pdfkit';
import {
  addToQueue, getQueue, isPollerRunning,
  startChatPoller, stopChatPoller,
  getSettings, upsertSettings,
} from '../services/magicLiveService.js';

// ── Subscription helper ───────────────────────────────────────────────────────
async function hasActiveSubscription(userId, db) {
  try {
    const result = await db.query(
      `SELECT id FROM user_subscriptions
       WHERE user_id = ? AND status = 'active'
       AND end_date >= DATE_SUB(NOW(), INTERVAL 1 DAY)
       ORDER BY end_date DESC LIMIT 1`,
      [userId]
    );
    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (_) { return null; }
}

// ── Page routes ───────────────────────────────────────────────────────────────

export async function getDashboard(req, res, db) {
  try {
    const userId   = req.user.id;
    const settings = await getSettings(userId, db);
    const running  = isPollerRunning(userId);
    const queue    = getQueue(userId);

    // YouTube connection status
    const { rows } = await db.query(
      `SELECT channel_name, channel_thumb FROM social_accounts
       WHERE user_id = ? AND platform = 'youtube' LIMIT 1`,
      [userId]
    );
    const ytAccount = rows[0] || null;

    const sub = await hasActiveSubscription(userId, db);

    res.render('magic-live/dashboard', {
      currentUser: req.user,
      settings,
      running,
      queue,
      ytAccount,
      hasPro: !!sub,
    });
  } catch (err) {
    console.error('[MagicLive] getDashboard error:', err.message);
    res.status(500).send('Error loading Magic Live dashboard');
  }
}

// Public — no auth middleware
export async function getOverlay(req, res, db) {
  const userId = parseInt(req.query.userId, 10);
  if (!userId) return res.status(400).send('Missing userId');

  try {
    const settings = await getSettings(userId, db);
    res.render('magic-live/overlay', { userId, settings });
  } catch (err) {
    console.error('[MagicLive] getOverlay error:', err.message);
    res.status(500).send('Error loading overlay');
  }
}

// ── API routes ────────────────────────────────────────────────────────────────

export async function apiAddName(req, res, db, io) {
  const userId = req.user.id;
  const { name } = req.body;
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Name required' });

  const clean = name.trim().slice(0, 50);
  if (!clean) return res.status(400).json({ error: 'Name required' });

  // Log to history
  db.query(
    'INSERT INTO magic_live_history (user_id, name, source) VALUES (?, ?, ?)',
    [userId, clean, 'manual']
  ).catch(() => {});

  // Emit directly to overlay — no queue
  io.to(`magic:${userId}`).emit('show-name', { name: clean });

  return res.json({ ok: true, name: clean });
}

export async function apiGetStatus(req, res, db) {
  const userId = req.user.id;
  try {
    const settings = await getSettings(userId, db);
    const { rows } = await db.query(
      `SELECT channel_name FROM social_accounts
       WHERE user_id = ? AND platform = 'youtube' LIMIT 1`,
      [userId]
    );
    res.json({
      running:          isPollerRunning(userId),
      queueLength:      getQueue(userId).length,
      animStyle:        settings.anim_style,
      animSpeed:        settings.anim_speed,
      youtubeConnected: rows.length > 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

export function apiGetQueue(req, res) {
  res.json({ queue: getQueue(req.user.id) });
}

export async function apiStartAuto(req, res, db, io) {
  const userId = req.user.id;

  const sub = await hasActiveSubscription(userId, db);
  if (!sub) return res.status(403).json({ error: 'PRO subscription required for Auto Magic' });

  if (isPollerRunning(userId)) return res.json({ ok: true, message: 'Already running' });

  try {
    const { rows } = await db.query(
      `SELECT access_token, refresh_token, token_expiry
       FROM social_accounts WHERE user_id = ? AND platform = 'youtube' LIMIT 1`,
      [userId]
    );
    if (!rows.length) return res.status(400).json({ error: 'YouTube account not connected' });

    const { access_token, refresh_token, token_expiry } = rows[0];
    await startChatPoller(userId, access_token, refresh_token, token_expiry, db, io);
    res.json({ ok: true });
  } catch (err) {
    console.error('[MagicLive] apiStartAuto error:', err.message);
    res.status(500).json({ error: err.message });
  }
}

export async function apiStopAuto(req, res, db) {
  await stopChatPoller(req.user.id, db);
  res.json({ ok: true });
}

export async function apiUpdateSettings(req, res, db) {
  const { animStyle, animSpeed, fontStyle } = req.body;
  const validStyles = ['handwriting', 'neon', 'fire', 'glow'];
  const validSpeeds = ['slow', 'normal', 'fast'];
  const validFonts  = ['bold', 'orbitron', 'dancing', 'pacifico', 'playfair', 'caveat'];

  if (animStyle && !validStyles.includes(animStyle)) return res.status(400).json({ error: 'Invalid style' });
  if (animSpeed && !validSpeeds.includes(animSpeed)) return res.status(400).json({ error: 'Invalid speed' });
  if (fontStyle  && !validFonts.includes(fontStyle))  return res.status(400).json({ error: 'Invalid font' });

  try {
    await upsertSettings(req.user.id, {
      animStyle: animStyle || 'neon',
      animSpeed: animSpeed || 'normal',
      fontStyle: fontStyle  || 'bold',
    }, db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// Kept for Auto Magic internal use
export async function apiShowNext(req, res, db, io) {
  const userId = req.user.id;
  const queue = getQueue(userId);
  if (!queue.length) return res.json({ ok: false, reason: 'Queue empty' });

  const { shiftQueue } = await import('../services/magicLiveService.js');
  const name = shiftQueue(userId);
  if (!name) return res.json({ ok: false, reason: 'Queue empty' });

  io.to(`magic:${userId}`).emit('show-name', { name });
  io.to(`magic:${userId}`).emit('queue-update', getQueue(userId));

  res.json({ ok: true, name, queue: getQueue(userId) });
}

export async function apiClearQueue(req, res, io) {
  const { clearQueue } = await import('../services/magicLiveService.js');
  clearQueue(req.user.id);
  io.to(`magic:${req.user.id}`).emit('queue-update', []);
  io.to(`magic:${req.user.id}`).emit('clear-overlay');
  res.json({ ok: true });
}

// ── Public viewer submission ──────────────────────────────────────────────────

export async function getSubmitPage(req, res, db) {
  const targetUserId = parseInt(req.query.u, 10);
  if (!targetUserId) return res.status(400).send('Invalid link — missing user ID');
  try {
    const { rows } = await db.query('SELECT name FROM users WHERE id = ? AND is_active = 1 LIMIT 1', [targetUserId]);
    if (!rows.length) return res.status(404).send('Stream not found');
    res.render('magic-live/submit', {
      targetUserId,
      streamerName: rows[0].name.split(' ')[0],
    });
  } catch (err) {
    res.status(500).send('Error loading page');
  }
}

// In-memory rate limit: ip:userId → last submit timestamp
const submitCooldowns = new Map();
const SUBMIT_COOLDOWN_MS = 30_000;

export async function postSubmit(req, res, db, io) {
  const { name, userId: rawId } = req.body;
  const targetUserId = parseInt(rawId, 10);

  if (!targetUserId || !name || typeof name !== 'string')
    return res.status(400).json({ ok: false, message: 'Missing name or user ID' });

  const clean = name.trim().replace(/[<>]/g, '').slice(0, 40);
  if (!clean) return res.status(400).json({ ok: false, message: 'Name cannot be empty' });

  // Rate limit per IP per streamer
  const key = `${req.ip}:${targetUserId}`;
  const last = submitCooldowns.get(key) || 0;
  const now  = Date.now();
  if (now - last < SUBMIT_COOLDOWN_MS) {
    const wait = Math.ceil((SUBMIT_COOLDOWN_MS - (now - last)) / 1000);
    return res.json({ ok: false, error: 'wait', message: `Please wait ${wait}s before submitting again.` });
  }
  submitCooldowns.set(key, now);

  // Verify target user exists
  try {
    const { rows } = await db.query('SELECT id FROM users WHERE id = ? AND is_active = 1 LIMIT 1', [targetUserId]);
    if (!rows.length) return res.json({ ok: false, message: 'Stream not found' });
  } catch (_) {
    return res.status(500).json({ ok: false, message: 'Server error' });
  }

  // Log to history
  db.query(
    'INSERT INTO magic_live_history (user_id, name, source) VALUES (?, ?, ?)',
    [targetUserId, clean, 'manual']
  ).catch(() => {});

  // Emit to overlay
  io.to(`magic:${targetUserId}`).emit('show-name', { name: clean });
  return res.json({ ok: true });
}

// ── Page Navigator ────────────────────────────────────────────────────────────

export function apiNavPage(req, res, io) {
  const { direction } = req.body;
  if (!['prev', 'next', 'live'].includes(direction)) {
    return res.status(400).json({ error: 'Invalid direction' });
  }
  io.to(`magic:${req.user.id}`).emit('nav-page', { direction });
  res.json({ ok: true });
}

// ── PDF Export ────────────────────────────────────────────────────────────────

export async function exportPdf(req, res, db) {
  const userId = req.user.id;
  const { from, to } = req.query;

  let rows;
  try {
    let sql = `SELECT name, source, created_at FROM magic_live_history WHERE user_id = ?`;
    const params = [userId];
    if (from) { sql += ` AND created_at >= ?`; params.push(from); }
    if (to)   { sql += ` AND created_at <= DATE_ADD(?, INTERVAL 1 DAY)`; params.push(to); }
    sql += ` ORDER BY created_at ASC`;
    ({ rows } = await db.query(sql, params));
  } catch (err) {
    return res.status(500).send('Error fetching history');
  }

  const streamerName = req.user.name || 'Streamer';
  const dateLabel = from && to
    ? `${from} to ${to}`
    : from ? `From ${from}` : to ? `Until ${to}` : 'All time';

  const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="magic-live-guestbook.pdf"`);
  doc.pipe(res);

  const PW = 595.28, PH = 841.89;
  const ML = 52, MR = 52, MT = 40;
  const COL1_X = ML, COL2_X = PW / 2 + 10;
  const COL_W = PW / 2 - ML - 10;
  const HEADER_H = 160;
  const NAME_SIZE = 13;
  const LINE_H_PDF = 22;
  const NAMES_START_Y = HEADER_H + MT + 16;
  const MAX_Y = PH - 55;
  const NAMES_PER_COL = Math.floor((MAX_Y - NAMES_START_Y) / LINE_H_PDF);

  // ── Draw page header ──
  function drawHeader(pageN, totalPages) {
    // Purple gradient band
    doc.rect(0, 0, PW, HEADER_H)
       .fillColor('#4c1d95').fill();
    doc.rect(0, HEADER_H - 6, PW, 6)
       .fillColor('#7c3aed').fill();

    doc.fillColor('#e9d5ff')
       .font('Helvetica-Bold').fontSize(9)
       .text('✦ MAGIC LIVE GUESTBOOK', ML, 32, { align: 'left' });

    doc.fillColor('#ffffff')
       .font('Helvetica-Bold').fontSize(26)
       .text(streamerName + "'s Stream", ML, 50);

    doc.fillColor('#c4b5fd')
       .font('Helvetica').fontSize(11)
       .text(dateLabel + '   ·   ' + rows.length + ' names', ML, 84);

    // Page number top-right
    doc.fillColor('rgba(255,255,255,0.5)')
       .font('Helvetica').fontSize(9)
       .text(`Page ${pageN} of ${totalPages}`, 0, 32, { align: 'right', width: PW - ML });

    // Column headers
    const hy = HEADER_H + MT;
    doc.fillColor('#7c3aed').font('Helvetica-Bold').fontSize(8)
       .text('NAME', COL1_X, hy)
       .text('NAME', COL2_X, hy);

    doc.moveTo(ML, hy + 13).lineTo(PW - MR, hy + 13)
       .strokeColor('#e9d5ff').lineWidth(0.5).stroke();

    // Center divider
    doc.moveTo(PW / 2, NAMES_START_Y - 4).lineTo(PW / 2, MAX_Y)
       .strokeColor('#ede9fe').lineWidth(0.5).stroke();
  }

  // ── Footer ──
  function drawFooter() {
    doc.fillColor('#9ca3af').font('Helvetica').fontSize(8)
       .text('Generated by SmrAI Studio — smraistudio.com', ML, PH - 30);
  }

  // Paginate names into 2-column chunks
  const namesPerPage = NAMES_PER_COL * 2;
  const totalPages   = Math.max(1, Math.ceil(rows.length / namesPerPage));

  for (let pg = 0; pg < totalPages; pg++) {
    if (pg > 0) doc.addPage({ size: 'A4', margin: 0 });
    drawHeader(pg + 1, totalPages);
    drawFooter();

    const chunk = rows.slice(pg * namesPerPage, (pg + 1) * namesPerPage);

    chunk.forEach((row, i) => {
      const col    = i < NAMES_PER_COL ? 0 : 1;
      const rowIdx = i < NAMES_PER_COL ? i : i - NAMES_PER_COL;
      const x      = col === 0 ? COL1_X : COL2_X;
      const y      = NAMES_START_Y + rowIdx * LINE_H_PDF;

      // Subtle alternating tint
      if (rowIdx % 2 === 0) {
        doc.rect(col === 0 ? ML - 4 : COL2_X - 4, y - 3,
                 COL_W, LINE_H_PDF - 2)
           .fillColor('#f5f3ff').fill();
      }

      // Number
      doc.fillColor('#a78bfa').font('Helvetica').fontSize(8)
         .text(String(pg * namesPerPage + i + 1).padStart(3, ' ') + '.', x, y + 2);

      // Name
      const srcIcon = row.source === 'chat' ? '💬' : '✍️';
      doc.fillColor('#1f0050').font('Helvetica-Bold').fontSize(NAME_SIZE)
         .text(row.name, x + 26, y, { width: COL_W - 26, ellipsis: true, lineBreak: false });

      // Source icon tiny
      doc.fillColor('#a78bfa').font('Helvetica').fontSize(7.5)
         .text(srcIcon, x + 26 + COL_W - 42, y + 4);
    });

    if (rows.length === 0) {
      doc.fillColor('#9ca3af').font('Helvetica').fontSize(13)
         .text('No names found for the selected period.', 0, NAMES_START_Y + 40, { align: 'center', width: PW });
    }
  }

  doc.end();
}
