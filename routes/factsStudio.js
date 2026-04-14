import express from 'express';
import {
  getEditor,
  apiList,
  apiSave,
  apiDelete,
  apiUploadBg,
  apiAiHighlight,
} from '../controllers/factsStudioController.js';

export default function factsStudioRouter(db, upload) {
  const router = express.Router();

  router.get('/',              (req, res) => getEditor(req, res, db));
  router.get('/list',          (req, res) => apiList(req, res, db));
  router.post('/save',         (req, res) => apiSave(req, res, db));
  router.delete('/:id',        (req, res) => apiDelete(req, res, db));
  router.post('/upload-bg',    upload.single('bg'), (req, res) => apiUploadBg(req, res));
  router.post('/ai-highlight', (req, res) => apiAiHighlight(req, res));

  return router;
}
