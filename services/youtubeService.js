/**
 * youtubeService.js
 * Upload a completed reel to a user's connected YouTube channel.
 * Uses the YouTube Data API v3 resumable upload (no googleapis package needed).
 */

import fs       from 'fs';
import path     from 'path';
import axios    from 'axios';
import FormData from 'form-data';

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const UPLOAD_ENDPOINT = 'https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status';

/**
 * Refresh an access token using the stored refresh_token.
 * Returns a fresh access_token.
 */
async function refreshAccessToken(refreshToken) {
  const res = await axios.post(
    TOKEN_ENDPOINT,
    new URLSearchParams({
      grant_type:    'refresh_token',
      refresh_token: refreshToken,
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
    }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  return res.data.access_token;
}

/**
 * Upload a reel video to YouTube.
 *
 * @param {object} opts
 *   accessToken   - current access token (will be refreshed if stale)
 *   refreshToken  - stored refresh token
 *   tokenExpiry   - unix ms when access token expires
 *   videoPath     - absolute path to the .mp4 file
 *   title         - video title
 *   description   - video description / caption
 *   tags          - string[] hashtag list (without #)
 * @returns {{ youtubeVideoId, youtubeUrl }}
 */
export async function uploadToYouTube({ accessToken, refreshToken, tokenExpiry, videoPath, title, description, tags = [] }) {
  // Refresh if token expires within 2 minutes
  let token = accessToken;
  if (!token || Date.now() > (tokenExpiry || 0) - 120_000) {
    if (!refreshToken) throw new Error('No refresh token available — user must reconnect YouTube.');
    token = await refreshAccessToken(refreshToken);
  }

  const fileSize = fs.statSync(videoPath).size;

  // Step 1: Initiate resumable upload — get the upload URL
  const initRes = await axios.post(
    UPLOAD_ENDPOINT,
    {
      snippet: {
        title:       title || 'AI Generated Reel',
        description: description || '',
        tags:        tags.slice(0, 500).map(t => t.replace(/^#/, '')),
        categoryId:  '22', // People & Blogs
      },
      status: {
        privacyStatus:           'public',
        selfDeclaredMadeForKids: false,
      },
    },
    {
      headers: {
        Authorization:           `Bearer ${token}`,
        'Content-Type':          'application/json',
        'X-Upload-Content-Type': 'video/mp4',
        'X-Upload-Content-Length': fileSize,
      },
    }
  );

  const uploadUrl = initRes.headers.location;
  if (!uploadUrl) throw new Error('YouTube did not return an upload URL.');

  // Step 2: Upload the video binary
  const fileStream = fs.createReadStream(videoPath);
  const uploadRes  = await axios.put(uploadUrl, fileStream, {
    headers: {
      'Content-Type':   'video/mp4',
      'Content-Length': fileSize,
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });

  const videoId  = uploadRes.data?.id;
  if (!videoId) throw new Error('YouTube upload succeeded but no video ID returned.');

  return {
    youtubeVideoId: videoId,
    youtubeUrl:     `https://youtu.be/${videoId}`,
  };
}
