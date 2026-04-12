import express from 'express';
import {
  getDashboard,
  apiAddName,
  apiGetStatus,
  apiGetQueue,
  apiStartAuto,
  apiStopAuto,
  apiUpdateSettings,
  apiShowNext,
  apiClearQueue,
  exportPdf,
  apiNavPage,
  apiUpdateHeader,
  apiShoutout,
  apiPollStart,
  apiPollReveal,
  apiPollEnd,
  apiPollStatus,
} from '../controllers/magicLiveController.js';

export default function magicLiveRouter(db, io) {
  const router = express.Router();

  // Dashboard
  router.get('/', (req, res) => getDashboard(req, res, db));

  // API
  router.post('/api/add',       (req, res) => apiAddName(req, res, db, io));
  router.post('/api/start',     (req, res) => apiStartAuto(req, res, db, io));
  router.post('/api/stop',      (req, res) => apiStopAuto(req, res, db));
  router.get('/api/status',     (req, res) => apiGetStatus(req, res, db));
  router.get('/api/queue',      (req, res) => apiGetQueue(req, res));
  router.post('/api/settings',  (req, res) => apiUpdateSettings(req, res, db));
  router.post('/api/show-next', (req, res) => apiShowNext(req, res, db, io));
  router.post('/api/clear',     (req, res) => apiClearQueue(req, res, io));
  router.get('/api/export-pdf', (req, res) => exportPdf(req, res, db));
  router.post('/api/nav-page',     (req, res) => apiNavPage(req, res, io));
  router.post('/api/update-header', (req, res) => apiUpdateHeader(req, res, db, io));

  // Shoutout
  router.post('/api/shoutout',     (req, res) => apiShoutout(req, res, io));

  // Live Poll
  router.post('/api/poll/start',   (req, res) => apiPollStart(req, res, io));
  router.post('/api/poll/reveal',  (req, res) => apiPollReveal(req, res, io));
  router.post('/api/poll/end',     (req, res) => apiPollEnd(req, res, io));
  router.get('/api/poll/status',   (req, res) => apiPollStatus(req, res));

  return router;
}
