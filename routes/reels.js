import express from 'express';
import {
  getCreatePage,
  getLoadingPage,
  getResultPage,
  getPricingPage,
  generateReel,
  getReelStatus,
} from '../controllers/reelController.js';

export default function reelsRouter(db) {
  const router = express.Router();

  // ── Page routes ──────────────────────────────────────────────────────────
  router.get('/', async (req, res) => {
    try {
      const [channelProof] = await db.query(`SELECT * FROM reels_channel_proof ORDER BY sort_order, created_at DESC`);
      const [nicheConfig]  = await db.query(`SELECT * FROM reels_niche_config`);
      const nicheMap = Object.fromEntries(nicheConfig.map(r => [r.niche_label, r]));
      res.render('reels/index', { title: 'AI Reel Generator', currentUser: req.user, channelProof, nicheMap });
    } catch {
      res.render('reels/index', { title: 'AI Reel Generator', currentUser: req.user, channelProof: [], nicheMap: {} });
    }
  });
  router.get('/create', getCreatePage);
  router.get('/loading/:id', (req, res) => getLoadingPage(req, res, db));
  router.get('/result/:id',  (req, res) => getResultPage(req, res, db));
  router.get('/pricing',     (req, res) => getPricingPage(req, res, db));

  // ── API routes ───────────────────────────────────────────────────────────
  router.post('/generate',   (req, res) => generateReel(req, res, db));
  router.get('/:id/status',  (req, res) => getReelStatus(req, res, db));

  return router;
}
