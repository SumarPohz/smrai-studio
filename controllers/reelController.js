import { generateScript, generateMetadata }        from '../services/openaiService.js';
import { generateTTS, AVAILABLE_VOICES }            from '../services/ttsService.js';
import { fetchPexelsVideos, downloadClips, cleanupTempClips } from '../services/videoService.js';
import { mergeReel }                                from '../services/ffmpegService.js';
import { uploadToYouTube }                          from '../services/youtubeService.js';
import path                                         from 'path';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Returns YYYY-MM-DD of this week's Monday */
function getWeekStart() {
  const d = new Date();
  const day = d.getDay(); // 0=Sun
  d.setDate(d.getDate() - (day === 0 ? 6 : day - 1));
  return d.toISOString().split('T')[0];
}

/**
 * Check whether a user may generate a new reel.
 * Returns { allowed: bool, free: bool, reason: string|null }
 */
async function canGenerateReel(userId, db) {
  // 1) Count all reels ever created by this user
  const countRes = await db.query(
    `SELECT COUNT(*) AS cnt FROM reels WHERE user_id = ? AND status != 'failed'`,
    [userId]
  );
  const totalReels = parseInt(countRes.rows[0]?.cnt || 0, 10);

  // First reel is always free
  if (totalReels === 0) return { allowed: true, free: true, reason: null };

  // 2) Must have an active subscription
  const subRes = await db.query(
    `SELECT id FROM reel_subscriptions
     WHERE user_id = ? AND status = 'active' AND current_period_end >= CURDATE()
     LIMIT 1`,
    [userId]
  );
  if (!subRes.rows.length) {
    return { allowed: false, free: false, reason: 'no_subscription' };
  }

  // 3) Weekly limit (3 per week)
  const weekStart = getWeekStart();
  const usageRes = await db.query(
    `SELECT videos_generated FROM reel_usage WHERE user_id = ? AND week_start = ?`,
    [userId, weekStart]
  );
  const used = parseInt(usageRes.rows[0]?.videos_generated || 0, 10);
  if (used >= 3) {
    return { allowed: false, free: false, reason: 'limit_reached' };
  }

  return { allowed: true, free: false, reason: null };
}

/** Increment the weekly usage counter */
async function incrementUsage(userId, db) {
  const weekStart = getWeekStart();
  await db.query(
    `INSERT INTO reel_usage (user_id, videos_generated, week_start)
     VALUES (?, 1, ?)
     ON DUPLICATE KEY UPDATE videos_generated = videos_generated + 1`,
    [userId, weekStart]
  );
}

/** Auto-post a completed reel to all connected social accounts */
async function autoPost(reelId, userId, meta, db) {
  // Fetch connected YouTube accounts for this user
  const { rows: accounts } = await db.query(
    `SELECT id, platform, channel_id, channel_name, access_token, refresh_token, token_expiry
     FROM social_accounts WHERE user_id = ? AND platform = 'youtube'`,
    [userId]
  );
  if (!accounts.length) return;

  // Resolve local video file path
  const videoPath = path.join(process.cwd(), 'public', 'videos', `${reelId}.mp4`);

  for (const account of accounts) {
    // Insert pending log row
    const logRes = await db.query(
      `INSERT INTO auto_posts (reel_id, user_id, social_account_id, platform, status)
       VALUES (?, ?, ?, 'youtube', 'pending')`,
      [reelId, userId, account.id]
    );
    const logId = logRes.insertId;

    try {
      const tags = Array.isArray(meta?.hashtags)
        ? meta.hashtags.map(t => t.replace(/^#/, ''))
        : [];

      const { youtubeVideoId, youtubeUrl } = await uploadToYouTube({
        accessToken:  account.access_token,
        refreshToken: account.refresh_token,
        tokenExpiry:  account.token_expiry,
        videoPath,
        title:        meta?.title || 'AI Reel',
        description:  meta?.caption || '',
        tags,
      });

      await db.query(
        `UPDATE auto_posts SET status='posted', platform_post_id=?, platform_url=? WHERE id=?`,
        [youtubeVideoId, youtubeUrl, logId]
      );
      console.log(`[AutoPost] Reel #${reelId} → YouTube: ${youtubeUrl}`);
    } catch (err) {
      await db.query(
        `UPDATE auto_posts SET status='failed', error_message=? WHERE id=?`,
        [err.message, logId]
      );
      console.error(`[AutoPost] Reel #${reelId} → YouTube failed:`, err.message);
    }
  }
}

// ─── Page Controllers ────────────────────────────────────────────────────────

export function getCreatePage(req, res) {
  res.render('reels/create', {
    title: 'AI Reel Generator',
    voices: AVAILABLE_VOICES,
    currentUser: req.user,
  });
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
 * Checks paywall, inserts DB record, fires background pipeline.
 */
export async function generateReel(req, res, db) {
  const { topic, voice = 'alloy' } = req.body;

  if (!topic || topic.trim().length < 3) {
    return res.status(400).json({ error: 'Please enter a topic (at least 3 characters).' });
  }
  if (topic.trim().length > 200) {
    return res.status(400).json({ error: 'Topic must be under 200 characters.' });
  }

  // ── Paywall check ──────────────────────────────────────────────────────────
  let access;
  try {
    access = await canGenerateReel(req.user.id, db);
  } catch (err) {
    console.error('[Reels] canGenerateReel error:', err);
    return res.status(500).json({ error: 'Could not check access. Please try again.' });
  }

  if (!access.allowed) {
    const message = access.reason === 'limit_reached'
      ? 'You have reached your 3 videos/week limit. Your limit resets next Monday.'
      : 'Subscribe to SmrAI Reels Starter (₹199/month) to generate more videos.';
    return res.status(402).json({
      error:    message,
      reason:   access.reason,
      redirect: '/reels/pricing',
    });
  }

  // ── Insert reel record ─────────────────────────────────────────────────────
  let reelId;
  try {
    const result = await db.query(
      'INSERT INTO reels (user_id, topic, status) VALUES (?, ?, ?)',
      [req.user.id, topic.trim(), 'processing']
    );
    reelId = result.insertId;
  } catch (err) {
    console.error('[Reels] DB insert error:', err);
    return res.status(500).json({ error: 'Failed to start reel generation. Please try again.' });
  }

  // Respond immediately — pipeline runs in background
  res.json({ reel_id: reelId, free: access.free });

  setImmediate(() => runPipeline(reelId, topic.trim(), voice, req.user.id, access.free, db));
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

async function runPipeline(reelId, topic, voice, userId, isFree, db) {
  console.log(`[Reels] Starting pipeline for reel #${reelId} — topic: "${topic}" free=${isFree}`);

  try {
    // Step 1: Script
    console.log(`[Reels] #${reelId} — Step 1: Generating script…`);
    const script = await generateScript(topic);
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

    // Step 4: Pexels videos
    console.log(`[Reels] #${reelId} — Step 4: Fetching Pexels videos…`);
    const videoUrls = await fetchPexelsVideos(topic, 4);

    // Step 5: Download clips
    console.log(`[Reels] #${reelId} — Step 5: Downloading ${videoUrls.length} clips…`);
    const clipPaths = await downloadClips(videoUrls, reelId);

    // Step 6: FFmpeg merge
    console.log(`[Reels] #${reelId} — Step 6: Merging with FFmpeg…`);
    await mergeReel(reelId, clipPaths, audioPath, script);

    // Step 7: Cleanup
    await cleanupTempClips(reelId);

    // Step 8: Mark completed + increment usage (skip for free video)
    const videoUrl = `/videos/${reelId}.mp4`;
    await db.query(
      'UPDATE reels SET status = ?, video_url = ? WHERE id = ?',
      ['completed', videoUrl, reelId]
    );

    if (!isFree) {
      await incrementUsage(userId, db);
    }

    // Step 9: Auto-post to connected social accounts (subscribed users only)
    if (!isFree) {
      await autoPost(reelId, userId, meta, db).catch(err =>
        console.error(`[Reels] #${reelId} — Auto-post error:`, err.message)
      );
    }

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
    await cleanupTempClips(reelId);
  }
}
