import PDFDocument from 'pdfkit';
import fs from 'fs';
import {
  addToQueue, getQueue, isPollerRunning,
  startChatPoller, stopChatPoller,
  getSettings, upsertSettings,
  startPoll, endPoll, getPoll,
  getCorrectVoterNames,
  startRandomShoutout, stopRandomShoutout,
  getRandomBuiltinNames,
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

export async function getDashboard(req, res, db, io) {
  try {
    const userId   = req.user.id;
    const settings = await getSettings(userId, db);
    const running  = isPollerRunning(userId);
    const queue    = getQueue(userId);

    // Re-arm random shoutout timer after server restart
    if (settings.random_shoutout_enabled) {
      const intervalMs = (settings.random_shoutout_interval || 120) * 1000;
      startRandomShoutout(userId, intervalMs, db, io);
    }

    // YouTube connection status
    const { rows } = await db.query(
      `SELECT channel_name, channel_thumb FROM social_accounts
       WHERE user_id = ? AND platform = 'youtube' LIMIT 1`,
      [userId]
    );
    const ytAccount = rows[0] || null;

    const sub = await hasActiveSubscription(userId, db);

    const sessionActive = !!(settings.session_active ?? 0);

    res.render('magic-live/dashboard', {
      currentUser: req.user,
      settings,
      running,
      queue,
      ytAccount,
      hasPro: !!sub,
      sessionActive,
    });
  } catch (err) {
    console.error('[MagicLive] getDashboard error:', err.message);
    res.status(500).send('Error loading Magic Live dashboard');
  }
}

// Public — no auth middleware
export async function getOverlay(req, res, db) {
  const userId   = parseInt(req.query.userId, 10);
  if (!userId) return res.status(400).send('Missing userId');
  const vertical = req.query.mode === 'vertical';

  try {
    const settings      = await getSettings(userId, db);
    const headerText    = (settings.header_text || "Q&A \u2014 Only 20% Can Answer!").replace(/</g, '&lt;');
    const sessionActive = !!(settings.session_active ?? 0);
    res.render('magic-live/overlay', { userId, settings, headerText, vertical, sessionActive });
  } catch (err) {
    console.error('[MagicLive] getOverlay error:', err.message);
    res.status(500).send('Error loading overlay');
  }
}

// ── API routes ────────────────────────────────────────────────────────────────

export async function apiAddName(req, res, db, io) {
  const userId = req.user.id;
  const { name, isSubscriber } = req.body;
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Name required' });

  const clean = name.trim().slice(0, 50);
  if (!clean) return res.status(400).json({ error: 'Name required' });

  const source = isSubscriber ? 'subscriber' : 'manual';
  db.query(
    'INSERT INTO magic_live_history (user_id, name, source) VALUES (?, ?, ?)',
    [userId, clean, source]
  ).catch(() => {});

  // Subscriber gets a special alert event; regular names go to the guestbook queue
  const event = isSubscriber ? 'show-subscriber' : 'show-name';
  io.to(`magic:${userId}`).emit(event, { name: clean });

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

export async function apiUpdateHeader(req, res, db, io) {
  let { headerText } = req.body;
  if (typeof headerText !== 'string') return res.status(400).json({ error: 'headerText required' });
  headerText = headerText.trim().slice(0, 80) || "Q&A \u2014 Only 20% Can Answer!";
  try {
    const s = await getSettings(req.user.id, db);
    await upsertSettings(req.user.id, {
      animStyle:  s.anim_style  || 'neon',
      animSpeed:  s.anim_speed  || 'normal',
      fontStyle:  s.font_style  || 'bold',
      headerText,
    }, db);
    io.to(`magic:${req.user.id}`).emit('update-header', { headerText });
    res.json({ ok: true, headerText });
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

// ── Shoutout ──────────────────────────────────────────────────────────────────

export function apiShoutout(req, res, io) {
  const { name } = req.body;
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Name required' });
  const clean = name.trim().slice(0, 50);
  if (!clean) return res.status(400).json({ error: 'Name required' });
  io.to(`magic:${req.user.id}`).emit('show-shoutout', { name: clean });
  return res.json({ ok: true });
}

// ── Live Poll ─────────────────────────────────────────────────────────────────

export function apiPollStart(req, res, io) {
  const { question, options, answer, duration } = req.body;
  if (!question || typeof question !== 'string') return res.status(400).json({ error: 'Question required' });
  if (!Array.isArray(options)) return res.status(400).json({ error: 'Options required' });
  const filtered = options.map(o => String(o || '').trim()).filter(Boolean).slice(0, 4);
  if (filtered.length < 2) return res.status(400).json({ error: 'At least 2 options required' });
  const answerIdx = ['A','B','C','D'].indexOf(answer);
  if (answerIdx < 0 || answerIdx >= filtered.length)
    return res.status(400).json({ error: 'Select a valid correct answer' });

  const q    = question.trim().slice(0, 80);
  const opts = filtered.map(o => o.slice(0, 40));
  const dur  = [30, 45, 60].includes(Number(duration)) ? Number(duration) : 60;
  startPoll(req.user.id, q, opts, answer);
  // answer is NOT sent to overlay — only revealed after countdown
  io.to(`magic:${req.user.id}`).emit('poll-start', { question: q, options: opts, duration: dur });
  return res.json({ ok: true });
}

export async function apiPollReveal(req, res, io, db) {
  endPoll(req.user.id);
  const p = getPoll(req.user.id);
  io.to(`magic:${req.user.id}`).emit('poll-reveal', {
    answer: p?.answer,
    votes:  p?.votes  || [],
    total:  p?.voters.size || 0,
  });
  return res.json({ ok: true, answer: p?.answer });
}

export function apiPollEnd(req, res, io) {
  endPoll(req.user.id);
  const p = getPoll(req.user.id);
  io.to(`magic:${req.user.id}`).emit('poll-end', {
    votes: p?.votes || [],
    total: p?.voters.size || 0,
  });
  return res.json({ ok: true });
}

export function apiPollStatus(req, res) {
  const p = getPoll(req.user.id);
  if (!p) return res.json({ active: false });
  res.json({
    active:   p.active,
    question: p.question,
    options:  p.options,
    votes:    p.votes,
    total:    p.voters.size,
    answer:   p.active ? null : p.answer, // hidden while voting, revealed after
  });
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

// ── Quiz Bank ─────────────────────────────────────────────────────────────────

// Simple CSV parser — handles quoted fields containing commas
function parseCsvLine(line) {
  const result = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuote && line[i + 1] === '"') { cur += '"'; i++; }
      else inQuote = !inQuote;
    } else if (ch === ',' && !inQuote) {
      result.push(cur.trim()); cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur.trim());
  return result;
}

export async function apiQuizUpload(req, res, db) {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlink(req.file.path, () => {}); // clean up temp file

    const lines = content.replace(/\r/g, '').split('\n').filter(Boolean);
    if (lines.length < 2) return res.status(400).json({ error: 'File is empty or has no data rows' });

    const rows = [];
    const VALID_ANSWERS = new Set(['A','B','C','D']);

    for (let i = 1; i < lines.length; i++) {
      const cols = parseCsvLine(lines[i]).map(c => c.replace(/^"|"$/g, '').trim());
      // Fixed format: question, option_a, option_b, option_c, answer  (always 5 columns)
      if (cols.length < 5) continue;
      const [question, option_a, option_b, option_c, answer] = cols;
      if (!question || !option_a || !option_b || !option_c) continue;
      const ans = answer.toUpperCase();
      if (!VALID_ANSWERS.has(ans)) continue;
      // A/B/C only — answer must be within 3 options
      if (ans === 'D') continue;
      rows.push([req.user.id, question.slice(0,255), option_a.slice(0,100),
                 option_b.slice(0,100), option_c.slice(0,100), null, ans]);
    }

    if (rows.length === 0) return res.status(400).json({ error: 'No valid rows found. Check the format.' });

    await db.query('DELETE FROM magic_live_quiz_bank WHERE user_id = ?', [req.user.id]);
    for (const row of rows) {
      await db.query(
        'INSERT INTO magic_live_quiz_bank (user_id,question,option_a,option_b,option_c,option_d,answer) VALUES (?,?,?,?,?,?,?)',
        row
      );
    }
    return res.json({ ok: true, count: rows.length });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to process file' });
  }
}

export async function apiQuizNext(req, res, db) {
  const userId = req.user.id;
  try {
    let { rows } = await db.query(
      'SELECT * FROM magic_live_quiz_bank WHERE user_id = ? AND used = 0 ORDER BY RAND() LIMIT 1',
      [userId]
    );
    // If all used, reset and retry
    if (!rows.length) {
      await db.query('UPDATE magic_live_quiz_bank SET used = 0 WHERE user_id = ?', [userId]);
      ({ rows } = await db.query(
        'SELECT * FROM magic_live_quiz_bank WHERE user_id = ? AND used = 0 ORDER BY RAND() LIMIT 1',
        [userId]
      ));
    }
    if (!rows.length) return res.json({ question: null, remaining: 0 });

    const q = rows[0];
    await db.query('UPDATE magic_live_quiz_bank SET used = 1 WHERE id = ?', [q.id]);
    const { rows: countRows } = await db.query(
      'SELECT COUNT(*) AS cnt FROM magic_live_quiz_bank WHERE user_id = ? AND used = 0', [userId]
    );
    return res.json({
      question: q.question,
      option_a: q.option_a,
      option_b: q.option_b,
      option_c: q.option_c || '',
      option_d: q.option_d || '',
      answer:   q.answer,
      remaining: countRows[0].cnt,
    });
  } catch (err) {
    return res.status(500).json({ error: 'DB error' });
  }
}

export async function apiQuizReset(req, res, db) {
  await db.query('UPDATE magic_live_quiz_bank SET used = 0 WHERE user_id = ?', [req.user.id]).catch(() => {});
  const { rows } = await db.query(
    'SELECT COUNT(*) AS cnt FROM magic_live_quiz_bank WHERE user_id = ?', [req.user.id]
  );
  return res.json({ ok: true, count: rows[0]?.cnt || 0 });
}

export async function apiQuizCount(req, res, db) {
  try {
    const { rows } = await db.query(
      'SELECT COUNT(*) AS total, SUM(used=0) AS remaining FROM magic_live_quiz_bank WHERE user_id = ?',
      [req.user.id]
    );
    return res.json({ total: rows[0].total || 0, remaining: rows[0].remaining || 0 });
  } catch (_) {
    return res.json({ total: 0, remaining: 0 });
  }
}

// ── Name Bank ─────────────────────────────────────────────────────────────────

export async function apiNamesUpload(req, res, db) {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlink(req.file.path, () => {});

    const names = content.replace(/\r/g, '').split('\n')
      .map(l => l.replace(/^"|"$/g, '').trim())
      .filter(n => n && n.length <= 100)
      .slice(0, 500); // cap at 500 names

    if (names.length === 0) return res.status(400).json({ error: 'No valid names found' });

    await db.query('DELETE FROM magic_live_name_bank WHERE user_id = ?', [req.user.id]);
    for (const name of names) {
      await db.query('INSERT INTO magic_live_name_bank (user_id, name) VALUES (?, ?)', [req.user.id, name]);
    }
    return res.json({ ok: true, count: names.length });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to process file' });
  }
}

export async function apiNamesCount(req, res, db) {
  try {
    const { rows } = await db.query(
      'SELECT COUNT(*) AS cnt FROM magic_live_name_bank WHERE user_id = ?', [req.user.id]
    );
    return res.json({ count: rows[0]?.cnt || 0 });
  } catch (_) {
    return res.json({ count: 0 });
  }
}

// ── Random Shoutout Toggle ────────────────────────────────────────────────────

export async function apiPollWinners(req, res, io, db) {
  const userId = req.user.id;
  let names = (req.body.names || []).map(n => String(n).trim()).filter(Boolean).slice(0, 20);

  // If admin submitted empty list, use random names now
  if (names.length === 0) {
    try {
      const { rows: s } = await db.query(
        'SELECT correct_shoutout_count FROM magic_live_settings WHERE user_id = ?',
        [userId]
      );
      const maxCount = s[0]?.correct_shoutout_count ?? 5;
      if (maxCount > 0) {
        // Try name bank first, fall back to built-in pool
        const { rows: nb } = await db.query(
          'SELECT name FROM magic_live_name_bank WHERE user_id = ? ORDER BY RAND() LIMIT ?',
          [userId, maxCount]
        ).catch(() => ({ rows: [] }));
        if (nb.length > 0) {
          names = nb.map(r => r.name);
        } else {
          names = getRandomBuiltinNames(maxCount);
        }
      }
    } catch (_) {
      names = getRandomBuiltinNames(5);
    }
  }

  names.forEach((name, i) => {
    setTimeout(() => io.to(`magic:${userId}`).emit('show-shoutout', { name }), i * 3000);
  });

  return res.json({ ok: true, count: names.length });
}

export async function apiToggleRandomShoutout(req, res, db, io) {
  const { enabled, intervalSecs, correctShoutoutCount } = req.body;
  const userId = req.user.id;
  const isEnabled = !!enabled;
  const interval  = Math.max(30, Math.min(600, parseInt(intervalSecs) || 120));
  const csc       = Math.max(0, Math.min(20, parseInt(correctShoutoutCount) ?? 5));

  await db.query(
    `INSERT INTO magic_live_settings (user_id, random_shoutout_enabled, random_shoutout_interval, correct_shoutout_count)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       random_shoutout_enabled  = VALUES(random_shoutout_enabled),
       random_shoutout_interval = VALUES(random_shoutout_interval),
       correct_shoutout_count   = VALUES(correct_shoutout_count)`,
    [userId, isEnabled ? 1 : 0, interval, csc]
  ).catch(() => {});

  if (isEnabled) {
    startRandomShoutout(userId, interval * 1000, db, io);
  } else {
    stopRandomShoutout(userId);
  }

  return res.json({ ok: true, enabled: isEnabled, intervalSecs: interval, correctShoutoutCount: csc });
}

// ── Music List (for Auto Loop wizard) ────────────────────────────────────────
const MUSIC_META = {
  happy:    { name: 'Happy Rhythm',        gradient: 'linear-gradient(135deg,#f59e0b,#ef4444)' },
  scary:    { name: 'Dark Spirits',         gradient: 'linear-gradient(135deg,#7f1d1d,#450a0a)' },
  storm:    { name: 'Quiet Before Storm',   gradient: 'linear-gradient(135deg,#6366f1,#4338ca)' },
  peaceful: { name: 'Peaceful Vibes',       gradient: 'linear-gradient(135deg,#22c55e,#16a34a)' },
  symphony: { name: 'Brilliant Symphony',   gradient: 'linear-gradient(135deg,#8b5cf6,#7c3aed)' },
  shadows:  { name: 'Breathing Shadows',    gradient: 'linear-gradient(135deg,#312e81,#1e1b4b)' },
};

export async function apiMusicList(req, res, db) {
  try {
    const { rows } = await db.query(
      `SELECT id FROM reels_music_presets WHERE full_audio IS NOT NULL`
    );
    const list = rows.map(r => ({
      id:       r.id,
      name:     MUSIC_META[r.id]?.name     || r.id,
      gradient: MUSIC_META[r.id]?.gradient || 'linear-gradient(135deg,#27272a,#18181b)',
    }));
    return res.json({ ok: true, list });
  } catch (_) {
    return res.json({ ok: true, list: [] });
  }
}

// ── Session Toggle (overlay ON/OFF) ──────────────────────────────────────────
export async function apiSessionToggle(req, res, db, io) {
  const userId = req.user.id;
  const active = !!req.body.active;

  await db.query(
    `INSERT INTO magic_live_settings (user_id, session_active) VALUES (?, ?)
     ON DUPLICATE KEY UPDATE session_active = VALUES(session_active)`,
    [userId, active ? 1 : 0]
  ).catch(() => {});

  io.to(`magic:${userId}`).emit('session-toggle', { active });
  return res.json({ ok: true, active });
}
