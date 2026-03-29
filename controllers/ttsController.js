import { generateScript }            from '../services/geminiReelService.js';
import { generateTTS, AVAILABLE_VOICES } from '../services/ttsService.js';
import path                            from 'path';

export function getCreatePage(req, res) {
  res.render('tts/create', {
    title:       'Text to Voice — SmrAI Studio',
    voices:      AVAILABLE_VOICES,
    currentUser: req.user,
  });
}

export async function generateScriptHandler(req, res) {
  const { topic } = req.body;
  if (!topic || topic.trim().length < 3)
    return res.status(400).json({ error: 'Topic must be at least 3 characters.' });
  if (topic.trim().length > 300)
    return res.status(400).json({ error: 'Topic must be under 300 characters.' });

  try {
    const script = await generateScript(topic.trim(), {
      language: 'en',
      artStyle:  'cinematic',
      duration:  '30-40',
    });
    res.json({ script });
  } catch (err) {
    console.error('[TTS] generateScript error:', err.message);
    res.status(500).json({ error: 'Failed to generate script. Please try again.' });
  }
}

export async function generateAudioHandler(req, res, db) {
  const { script, voice = 'alloy' } = req.body;
  if (!script || script.trim().length < 10)
    return res.status(400).json({ error: 'Script is too short.' });
  if (!AVAILABLE_VOICES.includes(voice))
    return res.status(400).json({ error: 'Invalid voice selection.' });

  let ttsId;
  try {
    const { insertId } = await db.query(
      `INSERT INTO tts_audios (user_id, script, voice, status) VALUES (?, ?, ?, 'pending')`,
      [req.user.id, script.trim(), voice]
    );
    ttsId = insertId;
  } catch (err) {
    console.error('[TTS] DB insert error:', err.message);
    return res.status(500).json({ error: 'Failed to start audio generation.' });
  }

  try {
    // generateTTS names the file public/audio/{id}.mp3 — prefix with "tts-" to avoid collisions
    await generateTTS(script.trim(), voice, `tts-${ttsId}`);
    const audioUrl = `/audio/tts-${ttsId}.mp3`;
    await db.query(
      `UPDATE tts_audios SET audio_url = ?, status = 'completed' WHERE id = ?`,
      [audioUrl, ttsId]
    );
    res.json({ audio_url: audioUrl, tts_id: ttsId });
  } catch (err) {
    console.error('[TTS] generateTTS error:', err.message);
    await db.query(
      `UPDATE tts_audios SET status = 'failed' WHERE id = ?`,
      [ttsId]
    );
    res.status(500).json({ error: 'Failed to generate audio. Please try again.' });
  }
}

export async function downloadAudio(req, res, db) {
  const ttsId = parseInt(req.params.id, 10);
  if (!ttsId) return res.status(400).json({ error: 'Invalid audio ID.' });

  // Subscription check
  try {
    const { rows: subs } = await db.query(
      `SELECT id FROM user_subscriptions
       WHERE user_id = ? AND status = 'active' AND end_date >= NOW()
       LIMIT 1`,
      [req.user.id]
    );
    if (!subs.length) {
      return res.status(403).json({ error: 'Pro subscription required to download.' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Could not verify subscription.' });
  }

  try {
    const { rows } = await db.query(
      `SELECT audio_url FROM tts_audios WHERE id = ? AND user_id = ? AND status = 'completed'`,
      [ttsId, req.user.id]
    );
    if (!rows.length || !rows[0].audio_url) {
      return res.status(404).json({ error: 'Audio not found.' });
    }
    const filePath = path.join(process.cwd(), 'public', rows[0].audio_url);
    res.download(filePath, `smrai-voice-${ttsId}.mp3`);
  } catch (err) {
    console.error('[TTS] downloadAudio error:', err.message);
    res.status(500).json({ error: 'Download failed.' });
  }
}
