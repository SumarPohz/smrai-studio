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
  generateMediaReel,
  getReelStatus,
  approveReel,
  regenerateScript,
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

// Multer for user-uploaded media files (images/videos) for media reel mode
const userMediaDir = path.join(__dirname, '..', 'public', 'videos', 'temp', 'user-media');
if (!fs.existsSync(userMediaDir)) fs.mkdirSync(userMediaDir, { recursive: true });

const mediaUploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, userMediaDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const uid = req.user?.id || 'guest';
    cb(null, `media-${uid}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}${ext}`);
  },
});
const mediaUpload = multer({
  storage: mediaUploadStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime))$/.test(file.mimetype);
    cb(null, ok);
  },
});

// Multer for person photo upload (used during reel approval for image-to-video)
const personPhotoDir = path.join(__dirname, '..', 'public', 'videos', 'temp');
const personPhotoUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, personPhotoDir),
    filename:    (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
      cb(null, `person-${req.params.id}${ext}`);
    },
  }),
  limits:     { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, /image\/(jpeg|jpg|png|webp)/.test(file.mimetype)),
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
  router.get('/script-mapper', async (req, res) => {
    let walletBalance = 0, mediaReelPrice = 99;
    try {
      const [wRes, pRes] = await Promise.all([
        req.user ? db.query('SELECT wallet_balance FROM users WHERE id = ?', [req.user.id]) : Promise.resolve({ rows: [] }),
        db.query("SELECT value FROM admin_settings WHERE `key` = 'media_reel_price'"),
      ]);
      walletBalance  = parseFloat(wRes.rows?.[0]?.wallet_balance || 0);
      mediaReelPrice = parseInt(pRes.rows?.[0]?.value || '99', 10);
    } catch {}
    res.render('reels/script-mapper', {
      title:          'Script Visual Mapper — SmrAI Studio',
      currentUser:    req.user,
      voices:         AVAILABLE_VOICES,
      availableMusic: [],
      walletBalance,
      mediaReelPrice,
      razorpayKey:    process.env.RAZORPAY_KEY_ID,
    });
  });

  // ── API routes ───────────────────────────────────────────────────────────
  router.post('/generate',              (req, res) => generateReel(req, res, db));
  router.get('/:id/status',             (req, res) => getReelStatus(req, res, db));
  router.post('/:id/approve', personPhotoUpload.single('personPhoto'), (req, res) => approveReel(req, res, db));
  router.post('/:id/regenerate-script', (req, res) => regenerateScript(req, res, db));

  // Media reel — upload files first, then generate
  router.post('/upload-media', mediaUpload.array('media', 30), (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
    const files = req.files.map(f => ({
      path: f.path,
      mimetype: f.mimetype,
      originalname: f.originalname,
    }));
    res.json({ ok: true, files });
  });

  router.post('/generate-media', (req, res) => generateMediaReel(req, res, db));

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
