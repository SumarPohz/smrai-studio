import express from 'express';
import {
  getEditor, apiList, apiSave, apiDelete, apiUploadMedia,
} from '../controllers/studioController.js';

export default function studioRouter(db, upload) {
  const router = express.Router();
  router.get('/',              (req, res) => getEditor(req, res, db));
  router.get('/list',          (req, res) => apiList(req, res, db));
  router.post('/save',         (req, res) => apiSave(req, res, db));
  router.delete('/:id',        (req, res) => apiDelete(req, res, db));
  router.post('/upload-media', upload.single('media'), apiUploadMedia);
  return router;
}
