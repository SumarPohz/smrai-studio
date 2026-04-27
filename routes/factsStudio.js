import express from 'express';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  getEditor,
  apiList,
  apiSave,
  apiDelete,
  apiUploadBg,
  apiAiHighlight,
  mergeClips,
  mergeStatus,
} from '../controllers/factsStudioController.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default function factsStudioRouter(db, upload) {
  const router = express.Router();

  // Multer for WebM clip uploads (up to 30 clips × 50 MB each)
  const clipsUpload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) =>
        cb(null, path.join(process.cwd(), 'public', 'videos', 'temp')),
      filename: (_req, file, cb) =>
        cb(null, `fsc-${Date.now()}-${file.originalname}`),
    }),
    limits: { fileSize: 50 * 1024 * 1024 },
  });

  router.get('/',              (req, res) => getEditor(req, res, db));
  router.get('/list',          (req, res) => apiList(req, res, db));
  router.post('/save',         (req, res) => apiSave(req, res, db));
  router.delete('/:id',        (req, res) => apiDelete(req, res, db));
  router.post('/upload-bg',    upload.single('bg'), (req, res) => apiUploadBg(req, res));
  router.post('/ai-highlight', (req, res) => apiAiHighlight(req, res));

  router.post('/merge-clips',
    clipsUpload.fields([{ name: 'clips', maxCount: 30 }, { name: 'music', maxCount: 1 }]),
    (req, res) => mergeClips(req, res, db)
  );
  router.get('/merge-status/:jobId', (req, res) => mergeStatus(req, res));

  return router;
}
