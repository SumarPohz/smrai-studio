import express from 'express';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import {
  getCreatePage,
  getLoadingPage,
  getResultPage,
  getPricingPage,
  generateReel,
  getReelStatus,
} from '../controllers/reelController.js';
import { generateVoicePreview, AVAILABLE_VOICES } from '../services/ttsService.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Multer for user custom music uploads (temp, per-user)
const customMusicDir = path.join(__dirname, '..', 'public', 'videos', 'temp', 'music');
if (!fs.existsSync(customMusicDir)) fs.mkdirSync(customMusicDir, { recursive: true });

const customMusicStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, customMusicDir),
  filename: (req, file, cb) => {
    const ts  = Date.now();
    const uid = req.user?.id || 'anon';
    cb(null, `music-${uid}-${ts}${path.extname(file.originalname)}`);
  },
});
const customMusicUpload = multer({
  storage: customMusicStorage,
  limits:  { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, /mp3|wav|mpeg|audio/.test(file.mimetype)),
});

export default function reelsRouter(db) {
  const router = express.Router();

  // ── Page routes ──────────────────────────────────────────────────────────
  router.get('/', async (req, res) => {
    try {
      const { rows: channelProof } = await db.query(`SELECT * FROM reels_channel_proof ORDER BY sort_order, created_at DESC`);
      const { rows: nicheConfig }  = await db.query(`SELECT * FROM reels_niche_config`);
      const nicheMap = Object.fromEntries(nicheConfig.map(r => [r.niche_label, r]));
      res.render('reels/index', { title: 'AI Reel Generator', currentUser: req.user, channelProof, nicheMap });
    } catch {
      res.render('reels/index', { title: 'AI Reel Generator', currentUser: req.user, channelProof: [], nicheMap: {} });
    }
  });
  router.get('/create', (req, res) => getCreatePage(req, res, db));
  router.get('/loading/:id', (req, res) => getLoadingPage(req, res, db));
  router.get('/result/:id',  (req, res) => getResultPage(req, res, db));
  router.get('/pricing',     (req, res) => getPricingPage(req, res, db));

  // ── API routes ───────────────────────────────────────────────────────────
  router.post('/generate',   (req, res) => generateReel(req, res, db));
  router.get('/:id/status',  (req, res) => getReelStatus(req, res, db));

  // Custom music upload — returns absolute server path
  router.post('/upload-music', customMusicUpload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ path: req.file.path });
  });

  // Voice preview — generates & caches a short sample clip per voice
  router.get('/voice-preview/:voice', async (req, res) => {
    if (!AVAILABLE_VOICES.includes(req.params.voice)) {
      return res.status(400).json({ error: 'Invalid voice' });
    }
    try {
      const filePath = await generateVoicePreview(req.params.voice);
      res.sendFile(filePath);
    } catch (err) {
      console.error('[VoicePreview] Error:', err.message);
      res.status(500).json({ error: 'Failed to generate preview' });
    }
  });

  return router;
}
