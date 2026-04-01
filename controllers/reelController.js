import { generateScript }                           from '../services/geminiReelService.js';
import { generateMetadata }                         from '../services/openaiService.js';
import { generateTTS, AVAILABLE_VOICES }            from '../services/ttsService.js';
import { generateImages, cleanupTempImages }        from '../services/imageService.js';
import { mergeReelFromImages }                      from '../services/ffmpegService.js';
import path                                         from 'path';
import fs                                           from 'fs/promises';
import crypto                                       from 'crypto';

const ART_STYLES = ['cinematic','creepy','vibrant','disney','nature','urban','fantasy','historical'];

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

    // Check which preset music tracks have been uploaded by admin (stored in DB)
    const { rows: musicRows } = await db.query(`SELECT id FROM reels_music_presets WHERE full_audio IS NOT NULL`);
    const uploadedIds    = new Set(musicRows.map(r => r.id));
    const availableMusic = MUSIC_PRESETS.filter(p => uploadedIds.has(p[0]));

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
      'SELECT id, topic, title, hashtags, caption, video_url, status, created_at FROM reels WHERE id = ? AND user_id = ?',
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
    artStyle              = 'cinematic',
    captionStyle          = 'bold-stroke',
    duration              = '30-40',
    music                 = [],
    effects               = {},
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
      const [wRow, priceRow] = await Promise.all([
        db.query('SELECT wallet_balance FROM users WHERE id = ?', [req.user.id]),
        db.query("SELECT value FROM admin_settings WHERE `key` = 'price_reel_video'"),
      ]);
      const bal   = parseFloat(wRow.rows[0]?.wallet_balance || 0);
      const price = parseInt(priceRow.rows[0]?.value || '30', 10);
      if (bal < price) {
        return res.status(402).json({ error: 'Insufficient wallet balance.' });
      }
    } else {
      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(402).json({ requiresPayment: true, amount: 30 });
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
      `INSERT INTO reels (user_id, topic, status, language, art_style, caption_style, duration, music_tracks)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, topic.trim(), 'processing', language, artStyle, captionStyle, duration, JSON.stringify(music)]
    );
    reelId = result.insertId;
  } catch (err) {
    console.error('[Reels] DB insert error:', err);
    return res.status(500).json({ error: 'Failed to start reel generation. Please try again.' });
  }

  // ── Store payment record ───────────────────────────────────────────────────
  if (!isFree) {
    if (walletOnly) {
      const priceRow = await db.query("SELECT value FROM admin_settings WHERE `key` = 'price_reel_video'");
      const price    = parseInt(priceRow.rows[0]?.value || '30', 10);
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

  setImmediate(() => runPipeline(reelId, topic.trim(), voice, language, artStyle, captionStyle, duration, music, effects, exScript, req.user.id, isFree, db, customMusicPath));
}

/**
 * GET /reels/:id/status
 */
export async function getReelStatus(req, res, db) {
  const reelId = parseInt(req.params.id, 10);
  if (!reelId) return res.status(400).json({ error: 'Invalid reel ID' });

  try {
    const { rows } = await db.query(
      'SELECT id, status, video_url, error_message FROM reels WHERE id = ? AND user_id = ?',
      [reelId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reel not found' });

    const { status, video_url, error_message } = rows[0];
    return res.json({ status, video_url, error_message });
  } catch (err) {
    console.error('[Reels] getReelStatus error:', err);
    return res.status(500).json({ error: 'Failed to fetch reel status' });
  }
}

// ─── Background Pipeline ─────────────────────────────────────────────────────

async function runPipeline(reelId, topic, voice, language, artStyle, captionStyle, duration, music, effects, exScript, userId, isFree, db, customMusicPath = null) {
  console.log(`[Reels] Starting pipeline for reel #${reelId} — topic: "${topic}" lang=${language} art=${artStyle} free=${isFree}`);

  try {
    // Step 1: Script
    console.log(`[Reels] #${reelId} — Step 1: Generating script (Gemini, lang=${language}, art=${artStyle}, dur=${duration})…`);
    const script = await generateScript(topic, { language, artStyle, duration, exScript });
    await db.query('UPDATE reels SET script = ? WHERE id = ?', [script, reelId]);

    // Step 2: Metadata
    console.log(`[Reels] #${reelId} — Step 2: Generating metadata…`);
    const meta = await generateMetadata(script);
    await db.query(
      'UPDATE reels SET title = ?, hashtags = ?, caption = ? WHERE id = ?',
      [meta.title || '', JSON.stringify(meta.hashtags || []), meta.caption || '', reelId]
    );

    // Step 3: TTS
    console.log(`[Reels] #${reelId} — Step 3: Generating TTS (voice: ${voice})…`);
    const audioPath = await generateTTS(script, voice, reelId);

    // Step 4: Generate AI images from the script
    const providerRes = await db.query(
      "SELECT value FROM admin_settings WHERE `key` = 'reel_image_provider'"
    );
    const imgProvider = providerRes.rows[0]?.value || 'openai';
    const imageCount  = duration === '60-70' ? 12 : 8;
    const scriptLines = script.split(/\n+/).filter(Boolean);
    console.log(`[Reels] #${reelId} — Step 4: Generating ${imageCount} images via ${imgProvider} (artStyle=${artStyle})…`);
    const { imagePaths, imageDurations } = await generateImages(scriptLines, reelId, artStyle, imageCount, imgProvider);

    // Step 5: Resolve BGM music path — custom upload takes priority over preset
    let musicPath    = null;
    let tempMusicPath = null;
    if (customMusicPath) {
      try { await fs.access(customMusicPath); musicPath = customMusicPath; } catch {}
    }
    const musicId = Array.isArray(music) && music[0] ? music[0] : null;
    if (!musicPath && musicId) {
      const { rows: mRows } = await db.query(`SELECT full_audio FROM reels_music_presets WHERE id = ?`, [musicId]);
      if (mRows.length && mRows[0].full_audio) {
        tempMusicPath = path.join(process.cwd(), 'public', 'videos', 'temp', `bgm-${reelId}.mp3`);
        await fs.writeFile(tempMusicPath, mRows[0].full_audio);
        musicPath = tempMusicPath;
      }
    }

    // Step 6: FFmpeg merge (Ken Burns animation + captions)
    console.log(`[Reels] #${reelId} — Step 6: Merging ${imagePaths.length} images with FFmpeg (captionStyle=${captionStyle}, bgm=${musicPath ? musicId : 'none'})…`);
    await mergeReelFromImages(reelId, imagePaths, audioPath, script, { captionStyle, effects, musicPath, duration, imageDurations });

    // Step 7: Cleanup
    await cleanupTempImages(reelId);
    if (tempMusicPath) await fs.unlink(tempMusicPath).catch(() => {});

    // Step 8: Mark completed
    const videoUrl = `/videos/${reelId}.mp4`;
    await db.query(
      'UPDATE reels SET status = ?, video_url = ? WHERE id = ?',
      ['completed', videoUrl, reelId]
    );

    console.log(`[Reels] #${reelId} — Done! → ${videoUrl}`);
  } catch (err) {
    console.error(`[Reels] #${reelId} — Pipeline failed:`, err.message);
    try {
      await db.query(
        'UPDATE reels SET status = ?, error_message = ? WHERE id = ?',
        ['failed', err.message, reelId]
      );
    } catch (dbErr) {
      console.error(`[Reels] #${reelId} — Failed to update error status:`, dbErr.message);
    }
    await cleanupTempImages(reelId);
  }
}
