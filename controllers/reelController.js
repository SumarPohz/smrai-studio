import { generateScript, generateMetadata, generateDescription } from '../services/geminiReelService.js';
import { generateTTS, getWordTimestamps, getWordTimestampsViaGoogle, AVAILABLE_VOICES } from '../services/ttsService.js';
import { generateVideoClips, cleanupTempVideos }     from '../services/videoService.js';
import { mergeReelFromVideos }                      from '../services/ffmpegService.js';
import path                                         from 'path';
import fs                                           from 'fs/promises';
import crypto                                       from 'crypto';

// Expected directory for user-uploaded custom music — used for path validation
const CUSTOM_MUSIC_DIR = path.join(process.cwd(), 'public', 'videos', 'temp', 'music');

const ART_STYLES = ['cinematic','creepy','vibrant','disney','nature','urban','fantasy','historical','realistic'];

const MUSIC_PRESETS = [
  ['happy',    'Happy rhythm',       'Upbeat and energetic, perfect for positive content',           'linear-gradient(135deg,#f59e0b,#ef4444)'],
  ['scary',    'Dark Spirits',       'Haunting and terrifying atmosphere for horror content',        'linear-gradient(135deg,#1a0000,#7f1d1d)'],
  ['storm',    'Quiet before storm', 'Building tension and anticipation for dramatic reveals',       'linear-gradient(135deg,#6366f1,#4338ca)'],
  ['peaceful', 'Peaceful vibes',     'Calm and soothing background for relaxed storytelling',       'linear-gradient(135deg,#22c55e,#16a34a)'],
  ['symphony', 'Brilliant symphony', 'Orchestral and majestic for epic storytelling',               'linear-gradient(135deg,#8b5cf6,#7c3aed)'],
  ['shadows',  'Breathing shadows',  'Mysterious and eerie ambiance for suspenseful videos',        'linear-gradient(135deg,#312e81,#1e1b4b)'],
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Check if this is the user's first reel (free) or a paid generation.
 * Returns { free: bool }
 */
async function canGenerateReel(userId, db) {
  const countRes = await db.query(
    `SELECT COUNT(*) AS cnt FROM reels WHERE user_id = ? AND status != 'failed'`,
    [userId]
  );
  const total = parseInt(countRes.rows[0]?.cnt || 0, 10);
  return { free: total === 0 };
}

// ─── Page Controllers ────────────────────────────────────────────────────────

export async function getCreatePage(req, res, db) {
  try {
    const [countRes, walletRes] = await Promise.all([
      db.query(`SELECT COUNT(*) AS cnt FROM reels WHERE user_id = ? AND status != 'failed'`, [req.user.id]),
      db.query(`SELECT wallet_balance FROM users WHERE id = ?`, [req.user.id]),
    ]);
    const totalReels    = parseInt(countRes.rows[0]?.cnt || 0, 10);
    const walletBalance = parseFloat(walletRes.rows[0]?.wallet_balance || 0);

    // Check which art style GIFs have been uploaded by admin
    const artGifDir = path.join(process.cwd(), 'public', 'uploads', 'art-gifs');
    const artGifs   = {};
    for (const id of ART_STYLES) {
      try { await fs.access(path.join(artGifDir, `${id}.gif`)); artGifs[id] = `/uploads/art-gifs/${id}.gif`; }
      catch {}
    }

    // Fetch all uploaded music from DB — map to MUSIC_PRESETS for display info, fallback for custom IDs
    let availableMusic = [];
    try {
      const { rows: musicRows } = await db.query(`SELECT id FROM reels_music_presets WHERE full_audio IS NOT NULL ORDER BY created_at`);
      const presetMap = Object.fromEntries(MUSIC_PRESETS.map(p => [p[0], p]));
      availableMusic = musicRows.map(r => {
        if (presetMap[r.id]) return presetMap[r.id];
        const title = r.id.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        return [r.id, title, 'Background music', 'linear-gradient(135deg,#6366f1,#4338ca)'];
      });
    } catch { availableMusic = []; }

    res.render('reels/create', {
      title:       'AI Reel Generator',
      voices:      AVAILABLE_VOICES,
      currentUser: req.user,
      totalReels,
      walletBalance,
      artGifs,
      availableMusic,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    console.error('[Reels] getCreatePage error:', err);
    res.render('reels/create', {
      title:        'AI Reel Generator',
      voices:       AVAILABLE_VOICES,
      currentUser:  req.user,
      totalReels:   0,
      walletBalance: 0,
      artGifs:      {},
      availableMusic: [],
      razorpayKey:  process.env.RAZORPAY_KEY_ID,
    });
  }
}

export async function getLoadingPage(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId) return res.redirect('/reels/create');

  try {
    const { rows } = await db.query(
      'SELECT id, status, error_message FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.redirect('/reels/create');

    const reel = rows[0];
    if (reel.status === 'completed') return res.redirect(`/reels/result/${reelId}`);

    res.render('reels/loading', {
      title: 'Generating Your Reel…',
      reelId,
      reel,
      currentUser: req.user,
    });
  } catch (err) {
    console.error('[Reels] getLoadingPage error:', err);
    res.redirect('/reels/create');
  }
}

export async function getResultPage(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId) return res.redirect('/reels/create');

  try {
    const { rows } = await db.query(
      'SELECT id, topic, title, hashtags, caption, description, script, video_url, status, created_at FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.redirect('/reels/create');

    const reel = rows[0];
    if (reel.status === 'processing') return res.redirect(`/reels/loading/${reelId}`);
    if (reel.status === 'failed')     return res.redirect(`/reels/loading/${reelId}`);

    // Parse hashtags JSON array
    try { reel.hashtagsArr = JSON.parse(reel.hashtags || '[]'); }
    catch { reel.hashtagsArr = []; }

    // Check subscription status for UI
    const subRes = await db.query(
      `SELECT current_period_end FROM reel_subscriptions
       WHERE user_id = ? AND status = 'active' AND current_period_end >= CURDATE()
       ORDER BY current_period_end DESC LIMIT 1`,
      [req.user.id]
    );
    const isSubscribed = subRes.rows.length > 0;
    const periodEnd    = isSubscribed ? subRes.rows[0].current_period_end : null;

    // Total reels count (to decide whether to show paywall)
    const cntRes = await db.query(
      `SELECT COUNT(*) AS cnt FROM reels WHERE user_id = ? AND status != 'failed'`,
      [req.user.id]
    );
    const totalReels = parseInt(cntRes.rows[0]?.cnt || 0, 10);

    res.render('reels/result', {
      title: reel.title || 'Your Reel is Ready!',
      reel,
      isSubscribed,
      periodEnd,
      totalReels,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
      currentUser: req.user,
    });
  } catch (err) {
    console.error('[Reels] getResultPage error:', err);
    res.redirect('/reels/create');
  }
}

export async function getPricingPage(req, res, db) {
  try {
    const subRes = await db.query(
      `SELECT current_period_end FROM reel_subscriptions
       WHERE user_id = ? AND status = 'active' AND current_period_end >= CURDATE()
       ORDER BY current_period_end DESC LIMIT 1`,
      [req.user.id]
    );
    const isSubscribed = subRes.rows.length > 0;
    const periodEnd    = isSubscribed ? subRes.rows[0].current_period_end : null;

    const weekStart = getWeekStart();
    const usageRes  = await db.query(
      `SELECT videos_generated FROM reel_usage WHERE user_id = ? AND week_start = ?`,
      [req.user.id, weekStart]
    );
    const videosThisWeek = parseInt(usageRes.rows[0]?.videos_generated || 0, 10);

    // Optional preview reel passed as ?reel=<id>
    let previewVideo = null;
    const reelId = parseInt(req.query.reel, 10);
    if (reelId) {
      const reelRes = await db.query(
        `SELECT video_url, title FROM reels WHERE id = ? AND user_id = ? AND status = 'completed'`,
        [reelId, req.user.id]
      );
      if (reelRes.rows.length) previewVideo = reelRes.rows[0];
    }

    // Fallback: show their most recent completed reel
    if (!previewVideo) {
      const lastRes = await db.query(
        `SELECT video_url, title FROM reels WHERE user_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1`,
        [req.user.id]
      );
      if (lastRes.rows.length) previewVideo = lastRes.rows[0];
    }

    res.render('reels/pricing', {
      title: 'Reel Generator Plans — SmrAI Studio',
      isSubscribed,
      periodEnd,
      videosThisWeek,
      previewVideo,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
      currentUser: req.user,
    });
  } catch (err) {
    console.error('[Reels] getPricingPage error:', err);
    res.redirect('/reels');
  }
}

// ─── API Controllers ─────────────────────────────────────────────────────────

/**
 * POST /reels/generate
 * First reel is free; subsequent reels require verified Razorpay payment.
 */
export async function generateReel(req, res, db) {
  const {
    topic,
    voice                 = 'alloy',
    language              = 'en',
    artStyle              = 'realistic',
    duration              = '30-40',
    music                 = [],
    effects               = {},
    videoSpeed            = 1.0,
    storyHint             = '',
    exScript              = '',
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    walletOnly            = false,
    walletDeduction       = 0,
    customMusicPath       = null,
  } = req.body;

  if (!topic || topic.trim().length < 3) {
    return res.status(400).json({ error: 'Please enter a topic (at least 3 characters).' });
  }
  if (topic.trim().length > 200) {
    return res.status(400).json({ error: 'Topic must be under 200 characters.' });
  }

  // ── Free-first-reel check ──────────────────────────────────────────────────
  let isFree;
  try {
    const result = await canGenerateReel(req.user.id, db);
    isFree = result.free;
  } catch (err) {
    console.error('[Reels] canGenerateReel error:', err);
    return res.status(500).json({ error: 'Could not check access. Please try again.' });
  }

  // ── Payment verification (non-free videos) ────────────────────────────────
  if (!isFree) {
    if (walletOnly) {
      // Verify wallet has sufficient balance
      const priceKey = duration === '60-70' ? 'price_reel_long' : 'price_reel_short';
      const [wRow, priceRow] = await Promise.all([
        db.query('SELECT wallet_balance FROM users WHERE id = ?', [req.user.id]),
        db.query("SELECT value FROM admin_settings WHERE `key` = ?", [priceKey]),
      ]);
      const bal   = parseFloat(wRow.rows[0]?.wallet_balance || 0);
      const price = parseInt(priceRow.rows[0]?.value || (duration === '60-70' ? '700' : '350'), 10);
      if (bal < price) {
        return res.status(402).json({ error: 'Insufficient wallet balance.' });
      }
    } else {
      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(402).json({ requiresPayment: true, amount: duration === '60-70' ? 700 : 350 });
      }

      // Verify Razorpay signature
      const body        = `${razorpay_order_id}|${razorpay_payment_id}`;
      const expectedSig = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(body)
        .digest('hex');
      if (expectedSig !== razorpay_signature) {
        return res.status(400).json({ error: 'Invalid payment signature.' });
      }

      // Duplicate-payment guard
      const dup = await db.query(
        `SELECT id FROM reel_video_payments WHERE razorpay_payment_id = ?`,
        [razorpay_payment_id]
      );
      if (dup.rows.length) {
        return res.status(400).json({ error: 'This payment has already been used.' });
      }
    }
  }

  // ── Insert reel record ─────────────────────────────────────────────────────
  let reelId;
  try {
    const result = await db.query(
      `INSERT INTO reels (user_id, topic, status, language, art_style, duration, music_tracks)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, topic.trim(), 'processing', language, artStyle, duration, JSON.stringify(music)]
    );
    reelId = result.insertId;
  } catch (err) {
    console.error('[Reels] DB insert error:', err);
    return res.status(500).json({ error: 'Failed to start reel generation. Please try again.' });
  }

  // ── Store payment record ───────────────────────────────────────────────────
  if (!isFree) {
    if (walletOnly) {
      const priceKey = duration === '60-70' ? 'price_reel_long' : 'price_reel_short';
      const priceRow = await db.query("SELECT value FROM admin_settings WHERE `key` = ?", [priceKey]);
      const price    = parseInt(priceRow.rows[0]?.value || (duration === '60-70' ? '700' : '350'), 10);
      await db.query('UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?', [price, req.user.id])
        .catch(err => console.error('[Reels] Wallet deduct error:', err.message));
      await db.query(
        `INSERT INTO reel_video_payments (user_id, reel_id, amount) VALUES (?, ?, ?)`,
        [req.user.id, reelId, price]
      ).catch(err => console.error('[Reels] Payment record insert error:', err.message));
    } else {
      if (walletDeduction > 0) {
        await db.query('UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?', [walletDeduction, req.user.id])
          .catch(err => console.error('[Reels] Wallet partial deduct error:', err.message));
      }
      await db.query(
        `INSERT INTO reel_video_payments (user_id, reel_id, razorpay_order_id, razorpay_payment_id, razorpay_signature)
         VALUES (?, ?, ?, ?, ?)`,
        [req.user.id, reelId, razorpay_order_id, razorpay_payment_id, razorpay_signature]
      ).catch(err => console.error('[Reels] Payment record insert error:', err.message));
    }
  }

  // Respond immediately — pipeline runs in background
  res.json({ reel_id: reelId, free: isFree });

  setImmediate(() => runPipeline(reelId, topic.trim(), voice, language, artStyle, duration, music, effects, exScript, req.user.id, isFree, db, customMusicPath, videoSpeed, storyHint));
}

/**
 * GET /reels/:id/status
 */
export async function getReelStatus(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId) return res.status(400).json({ error: 'Invalid reel ID' });

  try {
    const { rows } = await db.query(
      'SELECT id, status, video_url, error_message, script, title, caption, hashtags, description FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reel not found' });

    const { status, video_url, error_message, script, title, caption, hashtags, description } = rows[0];

    // If failed, check if a refund was issued
    let refunded_amount = null;
    if (status === 'failed') {
      const { rows: payRows } = await db.query(
        'SELECT amount FROM reel_video_payments WHERE reel_id = ? AND refunded = 1 LIMIT 1',
        [reelId]
      );
      if (payRows.length) refunded_amount = parseFloat(payRows[0].amount);
    }

    return res.json({
      status,
      video_url,
      error_message,
      ...(status === 'script_ready' ? {
        script,
        title:       title       || '',
        caption:     caption     || '',
        description: description || '',
        hashtags:    (() => { try { return JSON.parse(hashtags || '[]'); } catch { return []; } })(),
      } : {}),
      ...(refunded_amount !== null ? { refunded_amount } : {}),
    });
  } catch (err) {
    console.error('[Reels] getReelStatus error:', err);
    return res.status(500).json({ error: 'Failed to fetch reel status' });
  }
}

// ─── Pipeline param persistence (temp JSON file between Phase 1 and Phase 2) ──

const PARAMS_DIR = path.join(process.cwd(), 'public', 'videos', 'temp');

async function savePipelineParams(reelId, params) {
  await fs.mkdir(PARAMS_DIR, { recursive: true });
  await fs.writeFile(path.join(PARAMS_DIR, `params-${reelId}.json`), JSON.stringify(params));
}
async function loadPipelineParams(reelId) {
  const raw = await fs.readFile(path.join(PARAMS_DIR, `params-${reelId}.json`), 'utf8');
  return JSON.parse(raw);
}
async function deletePipelineParams(reelId) {
  await fs.unlink(path.join(PARAMS_DIR, `params-${reelId}.json`)).catch(() => {});
}

// ─── Phase 1: Script + Metadata → status: script_ready ───────────────────────

async function runPipeline(reelId, topic, voice, language, artStyle, duration, music, effects, exScript, userId, isFree, db, customMusicPath = null, videoSpeed = 1.0, storyHint = '') {
  console.log(`[Reels] #${reelId} — Phase 1 start (topic: "${topic}")`);
  try {
    // Step 1: Script
    console.log(`[Reels] #${reelId} — Step 1: Generating script (lang=${language}, art=${artStyle}, dur=${duration})…`);
    const script = await generateScript(topic, { language, artStyle, duration, exScript, storyHint });
    await db.query('UPDATE reels SET script = ? WHERE id = ?', [script, reelId]);

    // Step 2: Metadata + Description (run in parallel)
    console.log(`[Reels] #${reelId} — Step 2: Generating metadata…`);
    const [meta, description] = await Promise.all([
      generateMetadata(script),
      generateDescription(script),
    ]);
    await db.query(
      'UPDATE reels SET title = ?, hashtags = ?, caption = ?, description = ? WHERE id = ?',
      [meta.title || '', JSON.stringify(meta.hashtags || []), meta.caption || '', description || '', reelId]
    );

    // Persist params needed by Phase 2
    await savePipelineParams(reelId, { voice, artStyle, duration, music, effects, customMusicPath, isFree, videoSpeed });

    // Signal that script is ready for user review
    await db.query("UPDATE reels SET status = 'script_ready' WHERE id = ?", [reelId]);
    console.log(`[Reels] #${reelId} — Script ready, awaiting user approval`);
  } catch (err) {
    console.error(`[Reels] #${reelId} — Phase 1 failed:`, err.message);
    await db.query(
      'UPDATE reels SET status = ?, error_message = ? WHERE id = ?',
      ['failed', err.message, reelId]
    ).catch(() => {});
  }
}

// ─── Phase 2: TTS → xAI → FFmpeg → completed ─────────────────────────────────

async function runPhase2(reelId, db) {
  console.log(`[Reels] #${reelId} — Phase 2 start (user approved)`);
  let customMusicPathUsed = null;
  let personImagePath     = null; // hoisted so catch block can clean it up
  try {
    // Load pipeline params saved during Phase 1
    const params = await loadPipelineParams(reelId);
    const { voice, artStyle, duration, music, effects, customMusicPath, videoSpeed = 1.0 } = params;
    personImagePath = params.personImagePath || null;

    // Read script from DB (user may have edited it before approving)
    const { rows: sRows } = await db.query('SELECT script FROM reels WHERE id = ?', [reelId]);
    if (!sRows.length) throw new Error('Reel not found');
    const script = sRows[0].script;

    // Step 3: Video clips — generate FIRST so we don't spend TTS credits if Veo rejects the script
    const { rows: pvRows } = await db.query(
      "SELECT value FROM admin_settings WHERE `key` = 'video_provider'"
    );
    const videoProvider = pvRows[0]?.value || 'xai';
    const scriptLines = script.split(/\n+/).filter(Boolean);
    console.log(`[Reels] #${reelId} — Step 3: Generating clips via ${videoProvider} (artStyle=${artStyle}${personImagePath ? ', person-image-to-video' : ''})…`);
    const { clipPaths, audioDurations } = await generateVideoClips(scriptLines, reelId, artStyle, duration, videoProvider, personImagePath);
    console.log(`[Reels] #${reelId} — Step 3: ${clipPaths.length} clips generated`);

    // Step 4: TTS — only runs if video succeeded
    const { rows: ttsProvRows } = await db.query(
      "SELECT value FROM admin_settings WHERE `key` = 'tts_provider'"
    );
    const ttsProvider = ttsProvRows[0]?.value || 'openai';
    console.log(`[Reels] #${reelId} — Step 4: Generating TTS (voice: ${voice}, provider: ${ttsProvider})…`);
    const audioPath = await generateTTS(script, voice, reelId, ttsProvider);

    // Step 4b: Word-level timestamps for karaoke captions
    let wtResult = null;
    if (ttsProvider === 'google') {
      console.log(`[Reels] #${reelId} — Step 4b: Getting caption timestamps via Google STT…`);
      wtResult = await getWordTimestampsViaGoogle(audioPath);
    } else {
      console.log(`[Reels] #${reelId} — Step 4b: Getting caption timestamps via Whisper…`);
      wtResult = await getWordTimestamps(audioPath);
    }
    const captionSegments = wtResult?.segments || null;
    const captionWords    = wtResult?.words    || null;

    // Step 5: Resolve BGM
    let musicPath     = null;
    let tempMusicPath = null;
    if (customMusicPath) {
      const resolved = path.resolve(customMusicPath);
      if (resolved.startsWith(CUSTOM_MUSIC_DIR + path.sep) || resolved.startsWith(CUSTOM_MUSIC_DIR + '/')) {
        try { await fs.access(resolved); musicPath = resolved; customMusicPathUsed = resolved; } catch {}
      }
    }
    const musicId = Array.isArray(music) && music[0] ? music[0] : null;
    if (!musicPath && musicId) {
      const { rows: mRows } = await db.query('SELECT full_audio FROM reels_music_presets WHERE id = ?', [musicId]);
      if (mRows.length && mRows[0].full_audio) {
        tempMusicPath = path.join(process.cwd(), 'public', 'videos', 'temp', `bgm-${reelId}.mp3`);
        await fs.writeFile(tempMusicPath, mRows[0].full_audio);
        musicPath = tempMusicPath;
      }
    }

    // Step 6: FFmpeg merge
    console.log(`[Reels] #${reelId} — Step 6: Merging ${clipPaths.length} clips + audio (bgm=${musicPath ? musicId : 'none'})…`);
    await mergeReelFromVideos(reelId, clipPaths, audioPath, script, { effects, musicPath, duration, audioDurations, captionSegments, captionWords, videoSpeed });

    // Step 7: Cleanup
    await cleanupTempVideos(reelId);
    if (tempMusicPath)       await fs.unlink(tempMusicPath).catch(() => {});
    if (customMusicPathUsed) await fs.unlink(customMusicPathUsed).catch(() => {});
    if (personImagePath)     await fs.unlink(personImagePath).catch(() => {});
    await deletePipelineParams(reelId);

    // Step 8: Mark completed
    const videoUrl = `/videos/${reelId}.mp4`;
    await db.query('UPDATE reels SET status = ?, video_url = ? WHERE id = ?', ['completed', videoUrl, reelId]);
    console.log(`[Reels] #${reelId} — Done! → ${videoUrl}`);
  } catch (err) {
    console.error(`[Reels] #${reelId} — Phase 2 failed:`, err.message);
    await db.query(
      'UPDATE reels SET status = ?, error_message = ? WHERE id = ?',
      ['failed', err.message, reelId]
    ).catch(() => {});
    await cleanupTempVideos(reelId);
    if (customMusicPathUsed) await fs.unlink(customMusicPathUsed).catch(() => {});
    if (personImagePath)     await fs.unlink(personImagePath).catch(() => {});
    await deletePipelineParams(reelId);

    // ── Auto-refund: add payment back to wallet ───────────────────────────────
    try {
      const { rows: payRows } = await db.query(
        'SELECT id, user_id, amount FROM reel_video_payments WHERE reel_id = ? AND refunded = 0 LIMIT 1',
        [reelId]
      );
      if (payRows.length) {
        const pay = payRows[0];
        await db.query('UPDATE reel_video_payments SET refunded = 1 WHERE id = ?', [pay.id]);
        await db.query('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', [pay.amount, pay.user_id]);
        await db.query(
          "INSERT INTO wallet_transactions (user_id, amount, type, reason, ref_id) VALUES (?, ?, 'credit', 'reel_gen_refund', ?)",
          [pay.user_id, pay.amount, String(reelId)]
        );
        console.log(`[Reels] #${reelId} — ₹${pay.amount} refunded to user #${pay.user_id}`);
      }
    } catch (refundErr) {
      console.error(`[Reels] #${reelId} — Refund failed:`, refundErr.message);
    }
  }
}

// ─── Approve reel (user reviewed script → trigger Phase 2) ───────────────────

export async function approveReel(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId || isNaN(reelId)) return res.status(400).json({ error: 'Invalid reel ID' });

  const { script: editedScript } = req.body;
  try {
    const { rows } = await db.query(
      'SELECT id, status FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reel not found' });
    if (rows[0].status !== 'script_ready') return res.status(400).json({ error: 'Reel is not awaiting approval' });

    // If user edited the script, persist it before Phase 2 reads it
    if (editedScript && editedScript.trim().length > 10) {
      await db.query('UPDATE reels SET script = ? WHERE id = ?', [editedScript.trim(), reelId]);
    }

    // If a person photo was uploaded, save its path into pipeline params
    if (req.file) {
      const existing = await loadPipelineParams(reelId).catch(() => ({}));
      existing.personImagePath = req.file.path;
      await savePipelineParams(reelId, existing);
    }

    await db.query("UPDATE reels SET status = 'processing' WHERE id = ?", [reelId]);
    res.json({ ok: true });
    setImmediate(() => runPhase2(reelId, db));
  } catch (err) {
    console.error('[Reels] approveReel error:', err);
    res.status(500).json({ error: 'Failed to approve reel' });
  }
}

// ─── Regenerate script (still in script_ready, no charge) ────────────────────

export async function regenerateScript(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId || isNaN(reelId)) return res.status(400).json({ error: 'Invalid reel ID' });

  try {
    const { rows } = await db.query(
      'SELECT id, status, topic, language, art_style, duration FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reel not found' });
    if (rows[0].status !== 'script_ready') return res.status(400).json({ error: 'Can only regenerate during script review' });

    const { topic, language, duration } = rows[0];
    const script = await generateScript(topic, { language, artStyle: 'realistic', duration });
    await db.query('UPDATE reels SET script = ? WHERE id = ?', [script, reelId]);
    res.json({ script });
  } catch (err) {
    console.error('[Reels] regenerateScript error:', err);
    res.status(500).json({ error: 'Failed to regenerate script' });
  }
}
