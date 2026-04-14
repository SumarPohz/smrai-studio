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
  apiQuizUpload,
  apiQuizNext,
  apiQuizReset,
  apiQuizCount,
  apiNamesUpload,
  apiNamesCount,
  apiPollWinners,
  apiToggleRandomShoutout,
  apiSessionToggle,
  apiMusicList,
} from '../controllers/magicLiveController.js';

export default function magicLiveRouter(db, io, upload) {
  const router = express.Router();

  // Dashboard
  router.get('/', (req, res) => getDashboard(req, res, db, io));

  // API
  router.post('/api/add',        (req, res) => apiAddName(req, res, db, io));
  router.post('/api/start',      (req, res) => apiStartAuto(req, res, db, io));
  router.post('/api/stop',       (req, res) => apiStopAuto(req, res, db));
  router.get('/api/status',      (req, res) => apiGetStatus(req, res, db));
  router.get('/api/queue',       (req, res) => apiGetQueue(req, res));
  router.post('/api/settings',   (req, res) => apiUpdateSettings(req, res, db));
  router.post('/api/show-next',  (req, res) => apiShowNext(req, res, db, io));
  router.post('/api/clear',      (req, res) => apiClearQueue(req, res, io));
  router.get('/api/export-pdf',  (req, res) => exportPdf(req, res, db));
  router.post('/api/nav-page',      (req, res) => apiNavPage(req, res, io));
  router.post('/api/update-header', (req, res) => apiUpdateHeader(req, res, db, io));

  // Shoutout
  router.post('/api/shoutout', (req, res) => apiShoutout(req, res, io));

  // Live Poll
  router.post('/api/poll/start',  (req, res) => apiPollStart(req, res, io));
  router.post('/api/poll/reveal', (req, res) => apiPollReveal(req, res, io, db));
  router.post('/api/poll/end',     (req, res) => apiPollEnd(req, res, io));
  router.post('/api/poll/winners', (req, res) => apiPollWinners(req, res, io, db));
  router.get('/api/poll/status',  (req, res) => apiPollStatus(req, res));

  // Quiz Bank
  router.post('/api/quiz/upload', upload.single('file'), (req, res) => apiQuizUpload(req, res, db));
  router.get('/api/quiz/next',    (req, res) => apiQuizNext(req, res, db));
  router.post('/api/quiz/reset',  (req, res) => apiQuizReset(req, res, db));
  router.get('/api/quiz/count',   (req, res) => apiQuizCount(req, res, db));

  // Name Bank
  router.post('/api/names/upload', upload.single('file'), (req, res) => apiNamesUpload(req, res, db));
  router.get('/api/names/count',   (req, res) => apiNamesCount(req, res, db));

  // Random Shoutout settings
  router.post('/api/settings/random-shoutout', (req, res) => apiToggleRandomShoutout(req, res, db, io));

  // Session toggle (overlay ON/OFF)
  router.post('/api/session/toggle', (req, res) => apiSessionToggle(req, res, db, io));

  // Music list for Auto Loop wizard
  router.get('/api/music/list', (req, res) => apiMusicList(req, res, db));

  return router;
}
