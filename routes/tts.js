import express from 'express';
import {
  getCreatePage,
  generateScriptHandler,
  generateAudioHandler,
  downloadAudio,
} from '../controllers/ttsController.js';

export default function ttsRouter(db) {
  const router = express.Router();

  router.get('/',                    getCreatePage);
  router.post('/generate-script',    generateScriptHandler);
  router.post('/generate-audio',     (req, res) => generateAudioHandler(req, res, db));
  router.get('/audio/:id/download',  (req, res) => downloadAudio(req, res, db));

  return router;
}
