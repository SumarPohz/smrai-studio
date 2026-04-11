import axios from 'axios';

// ── Per-user in-memory state ──────────────────────────────────────────────────
const userQueues  = new Map(); // userId → string[]
const userPollers = new Map(); // userId → { intervalId, liveChatId, processedIds: Set, pageToken: string|null, token: string }
const cooldowns   = new Map(); // userId → Map(viewerName → lastTriggeredMs)

const MAX_QUEUE     = 20;
const COOLDOWN_MS   = 60_000; // 1 min per viewer per user
const POLL_INTERVAL = 8_000;  // 8s

// ── Name validation ───────────────────────────────────────────────────────────
function sanitizeName(raw) {
  return String(raw || '').trim().replace(/[<>&"']/g, '').substring(0, 50);
}
function isValidName(name) {
  return name.length >= 1 && /^[\w\s\-'.]+$/u.test(name);
}

// ── Queue helpers ─────────────────────────────────────────────────────────────
export function addToQueue(userId, rawName, source = 'manual') {
  const name = sanitizeName(rawName);
  if (!isValidName(name)) return { ok: false, reason: 'Invalid name' };

  if (!userQueues.has(userId)) userQueues.set(userId, []);
  const q = userQueues.get(userId);

  if (q.length >= MAX_QUEUE)           return { ok: false, reason: 'Queue full' };
  if (q.includes(name))                return { ok: false, reason: 'Name already in queue' };

  q.push(name);
  return { ok: true, name, source };
}

export function getQueue(userId) {
  return [...(userQueues.get(userId) || [])];
}

export function shiftQueue(userId) {
  const q = userQueues.get(userId);
  if (!q || q.length === 0) return null;
  return q.shift();
}

export function clearQueue(userId) {
  userQueues.set(userId, []);
}

// ── Poller state ──────────────────────────────────────────────────────────────
export function isPollerRunning(userId) {
  return userPollers.has(userId);
}

// ── Token refresh ─────────────────────────────────────────────────────────────
async function refreshToken(refreshTokenStr) {
  const res = await axios.post('https://oauth2.googleapis.com/token', {
    client_id:     process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    refresh_token: refreshTokenStr,
    grant_type:    'refresh_token',
  });
  return { accessToken: res.data.access_token, expiry: Date.now() + res.data.expires_in * 1000 };
}

// ── YouTube Live Chat polling ─────────────────────────────────────────────────
export async function startChatPoller(userId, accessToken, refreshTokenStr, tokenExpiry, db, io) {
  if (userPollers.has(userId)) return; // already running

  let token      = accessToken;
  let expiry     = tokenExpiry || 0;
  let liveChatId = null;
  let pageToken  = null;
  const processedIds = new Set();

  async function ensureToken() {
    if (Date.now() > expiry - 120_000) {
      const refreshed = await refreshToken(refreshTokenStr);
      token  = refreshed.accessToken;
      expiry = refreshed.expiry;
      // Persist updated token to DB
      await db.query(
        `UPDATE social_accounts SET access_token = ?, token_expiry = ? WHERE user_id = ? AND platform = 'youtube'`,
        [token, expiry, userId]
      ).catch(() => {});
    }
    return token;
  }

  async function fetchLiveChatId() {
    const t = await ensureToken();
    const res = await axios.get('https://www.googleapis.com/youtube/v3/liveBroadcasts', {
      params: { part: 'snippet', broadcastStatus: 'active', mine: true },
      headers: { Authorization: `Bearer ${t}` },
    });
    const items = res.data.items || [];
    if (!items.length) return null;
    return items[0].snippet.liveChatId || null;
  }

  async function pollMessages() {
    try {
      const t = await ensureToken();

      // Find active broadcast if we don't have liveChatId yet
      if (!liveChatId) {
        liveChatId = await fetchLiveChatId();
        if (!liveChatId) return; // no active stream yet — keep retrying
      }

      const params = { part: 'snippet,authorDetails', liveChatId, maxResults: 200 };
      if (pageToken) params.pageToken = pageToken;

      const res = await axios.get('https://www.googleapis.com/youtube/v3/liveChat/messages', {
        params,
        headers: { Authorization: `Bearer ${t}` },
      });

      pageToken = res.data.nextPageToken || null;
      const items = res.data.items || [];

      for (const item of items) {
        const msgId = item.id;
        if (processedIds.has(msgId)) continue;
        processedIds.add(msgId);

        // Keep processedIds from growing unbounded
        if (processedIds.size > 2000) {
          const first = processedIds.values().next().value;
          processedIds.delete(first);
        }

        const text       = item.snippet?.displayMessage || '';
        const authorName = item.authorDetails?.displayName || '';

        if (!/\bmagic\b/i.test(text)) continue;

        // Cooldown check
        if (!cooldowns.has(userId)) cooldowns.set(userId, new Map());
        const userCooldown = cooldowns.get(userId);
        const lastTime     = userCooldown.get(authorName) || 0;
        if (Date.now() - lastTime < COOLDOWN_MS) continue;
        userCooldown.set(authorName, Date.now());

        const result = addToQueue(userId, authorName, 'chat');
        if (result.ok) {
          // Log to history
          db.query(
            'INSERT INTO magic_live_history (user_id, name, source) VALUES (?, ?, ?)',
            [userId, result.name, 'chat']
          ).catch(() => {});

          // Notify dashboard
          io.to(`magic:${userId}`).emit('queue-update', getQueue(userId));
        }
      }
    } catch (err) {
      if (err.response?.status === 403 || err.response?.status === 404) {
        // Stream ended or chat removed — reset liveChatId to retry on next poll
        liveChatId = null;
        pageToken  = null;
      }
      // Other errors: silently continue
    }
  }

  const intervalId = setInterval(pollMessages, POLL_INTERVAL);
  userPollers.set(userId, { intervalId, processedIds, get token() { return token; } });

  // Mark active in DB
  await db.query(
    `INSERT INTO magic_live_settings (user_id, is_active) VALUES (?, 1)
     ON DUPLICATE KEY UPDATE is_active = 1`,
    [userId]
  ).catch(() => {});
}

export async function stopChatPoller(userId, db) {
  const poller = userPollers.get(userId);
  if (poller) {
    clearInterval(poller.intervalId);
    userPollers.delete(userId);
  }
  cooldowns.delete(userId);

  await db.query(
    `UPDATE magic_live_settings SET is_active = 0 WHERE user_id = ?`,
    [userId]
  ).catch(() => {});
}

// ── Settings helpers ──────────────────────────────────────────────────────────
export async function getSettings(userId, db) {
  try {
    const { rows } = await db.query(
      'SELECT anim_style, anim_speed, font_style, is_active, header_text FROM magic_live_settings WHERE user_id = ? LIMIT 1',
      [userId]
    );
    if (rows.length) return rows[0];
  } catch (_) {
    // header_text column may not exist yet — fall back
    const { rows } = await db.query(
      'SELECT anim_style, anim_speed, font_style, is_active FROM magic_live_settings WHERE user_id = ? LIMIT 1',
      [userId]
    );
    if (rows.length) return rows[0];
  }
  return { anim_style: 'neon', anim_speed: 'normal', font_style: 'bold', is_active: 0 };
}

export async function upsertSettings(userId, { animStyle, animSpeed, fontStyle, headerText }, db) {
  try {
    await db.query(
      `INSERT INTO magic_live_settings (user_id, anim_style, anim_speed, font_style, header_text)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE anim_style = VALUES(anim_style), anim_speed = VALUES(anim_speed),
         font_style = VALUES(font_style), header_text = VALUES(header_text)`,
      [userId, animStyle, animSpeed, fontStyle || 'bold', headerText || "Tonight's Guests"]
    );
  } catch (_) {
    // header_text column missing — update without it
    await db.query(
      `INSERT INTO magic_live_settings (user_id, anim_style, anim_speed, font_style)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE anim_style = VALUES(anim_style), anim_speed = VALUES(anim_speed), font_style = VALUES(font_style)`,
      [userId, animStyle, animSpeed, fontStyle || 'bold']
    );
  }
}
