import express from 'express';
import {
  getCreatePage,
  getLoadingPage,
  getResultPage,
  generateWhiteboard,
  getStatus,
} from '../controllers/whiteboardController.js';

export default function whiteboardRouter(db) {
  const router = express.Router();

  router.get('/',            (req, res) => getCreatePage(req, res));
  router.get('/loading/:id', (req, res) => getLoadingPage(req, res, db));
  router.get('/result/:id',  (req, res) => getResultPage(req, res, db));
  router.post('/generate',   (req, res) => generateWhiteboard(req, res, db));
  router.get('/:id/status',  (req, res) => getStatus(req, res, db));

  return router;
}
