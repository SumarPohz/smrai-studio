import axios from 'axios';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import https from 'https';
import http from 'http';

/**
 * Search Pexels for portrait/vertical video clips related to the topic.
 * Returns an array of direct video file URLs.
 * @param {string} topic
 * @param {number} count - how many clips to fetch (default 4)
 * @returns {Promise<string[]>} array of video download URLs
 */
export async function fetchPexelsVideos(topic, count = 4) {
  const res = await axios.get('https://api.pexels.com/videos/search', {
    headers: { Authorization: process.env.PEXELS_API_KEY },
    params: {
      query: topic,
      per_page: Math.min(count + 2, 10), // fetch a few extra in case some have no valid file
      orientation: 'portrait',
    },
    timeout: 15000,
  });

  const urls = [];
  for (const video of res.data.videos) {
    if (urls.length >= count) break;

    // Prefer HD, fall back to SD
    const file = video.video_files
      .filter(f => ['hd', 'sd'].includes(f.quality))
      .sort((a, b) => b.width - a.width)[0];

    if (file?.link) urls.push(file.link);
  }

  if (urls.length === 0) {
    throw new Error(`No Pexels videos found for topic: "${topic}"`);
  }

  return urls;
}

/**
 * Download video clips from URLs to a temp directory.
 * @param {string[]} urls
 * @param {number} reelId
 * @returns {Promise<string[]>} local file paths
 */
export async function downloadClips(urls, reelId) {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  await fsp.mkdir(dir, { recursive: true });

  const paths = [];
  for (let i = 0; i < urls.length; i++) {
    const dest = path.join(dir, `clip_${i}.mp4`);
    await downloadFile(urls[i], dest);
    paths.push(dest);
  }

  return paths;
}

/**
 * Delete temp clip directory after merging.
 * @param {number} reelId
 */
export async function cleanupTempClips(reelId) {
  const dir = path.resolve(`./public/videos/temp/${reelId}`);
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch {
    // non-critical, ignore
  }
}

/**
 * Download a single file from a URL to a local path.
 * @param {string} url
 * @param {string} dest
 * @returns {Promise<void>}
 */
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const file = fs.createWriteStream(dest);

    const request = proto.get(url, (response) => {
      // Follow redirects (up to 5)
      if (response.statusCode === 301 || response.statusCode === 302) {
        file.close();
        fsp.unlink(dest).catch(() => {});
        return downloadFile(response.headers.location, dest).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        file.close();
        reject(new Error(`Failed to download video: HTTP ${response.statusCode}`));
        return;
      }

      response.pipe(file);
      file.on('finish', () => file.close(resolve));
    });

    request.on('error', (err) => {
      file.close();
      fsp.unlink(dest).catch(() => {});
      reject(err);
    });

    request.setTimeout(30000, () => {
      request.destroy();
      reject(new Error('Video download timed out'));
    });
  });
}
