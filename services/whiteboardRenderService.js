import { createCanvas } from 'canvas';
import path from 'path';
import fsp from 'fs/promises';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const W   = 1080;
const H   = 1920;
const PAD = 80;

const BG         = '#ffffff';
const TEXT_DARK  = '#1a1a2e';
const TEXT_BODY  = '#374151';
const TEXT_MUTED = '#9ca3af';
const EQ_COLOR   = '#059669';
const LINE_COLOR = '#e5e7eb';

const TITLE_Y_START      = 180;
const LINE_SPACING_TITLE = 88;
const LINE_SPACING_BODY  = 60;
const FOOTER_Y           = H - 60;

const ACCENT_PALETTE  = ['#7c3aed', '#FFD700', '#FF6B6B', '#4ECDC4', '#FF9F43'];
const ACCENT2_PALETTE = ['#a855f7', '#FF9F43', '#FF9F43', '#7c3aed', '#FF6B6B'];

function getAccent2(accent) {
  const idx = ACCENT_PALETTE.findIndex(a => a.toLowerCase() === accent.toLowerCase());
  return idx >= 0 ? ACCENT2_PALETTE[idx] : '#a855f7';
}

function hexToRgba(hex, alpha) {
  const h = hex.replace('#', '');
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

/**
 * Render N+1 progressive PNG frames for one scene.
 * frame0 = title only; frameK = title + elements[0..K-1]
 * Returns array of absolute PNG paths.
 */
export async function renderSceneFrames(scene, sceneIndex, totalScenes, tempDir) {
  await fsp.mkdir(tempDir, { recursive: true });
  const paths = [];
  const totalFrames = (scene.elements?.length || 0) + 1;

  for (let f = 0; f < totalFrames; f++) {
    const canvas = createCanvas(W, H);
    const ctx    = canvas.getContext('2d');
    drawFrame(ctx, scene, sceneIndex, totalScenes, f - 1);
    const p = path.join(tempDir, `frame-${sceneIndex}-${f}.png`);
    await fsp.writeFile(p, canvas.toBuffer('image/png'));
    paths.push(p);
  }
  return paths;
}

// ── Main drawing function ─────────────────────────────────────────────────────
function drawFrame(ctx, scene, sceneIndex, totalScenes, revealUpTo) {
  const accent  = scene.accent || ACCENT_PALETTE[sceneIndex % ACCENT_PALETTE.length];
  const accent2 = getAccent2(accent);

  // Background
  ctx.fillStyle = BG;
  ctx.fillRect(0, 0, W, H);

  // Dot grid
  ctx.fillStyle = '#dedede';
  for (let gx = 60; gx < W; gx += 70) {
    for (let gy = 60; gy < H; gy += 70) {
      ctx.beginPath();
      ctx.arc(gx, gy, 2.5, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // Top accent gradient bar
  const topGrad = ctx.createLinearGradient(0, 0, W, 0);
  topGrad.addColorStop(0, accent);
  topGrad.addColorStop(1, accent2);
  ctx.fillStyle = topGrad;
  ctx.fillRect(0, 0, W, 14);

  // Scene badge (top-right)
  ctx.fillStyle = accent;
  drawRoundRect(ctx, W - 180, 28, 150, 52, 26);
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 26px Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${sceneIndex + 1} / ${totalScenes}`, W - 105, 54);

  // App label (top-left)
  ctx.fillStyle = accent;
  ctx.font = 'bold 26px Arial';
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  ctx.fillText('SmrAI Studio', PAD, 54);

  // Title box
  ctx.font = 'bold 72px Arial';
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';
  const titleLines = wrapTextLines(ctx, scene.title || 'Untitled', W - PAD * 2 - 20, 'bold 72px Arial');
  const titleBoxH  = titleLines.length * LINE_SPACING_TITLE + 44;

  ctx.fillStyle = hexToRgba(accent, 0.12);
  drawRoundRect(ctx, PAD - 16, TITLE_Y_START - 20, W - (PAD - 16) * 2, titleBoxH, 16);
  ctx.fillStyle = accent;
  ctx.fillRect(PAD - 16, TITLE_Y_START - 20, 7, titleBoxH);

  ctx.fillStyle = TEXT_DARK;
  let ty = TITLE_Y_START;
  for (const line of titleLines) {
    ctx.fillText(line, PAD + 12, ty);
    ty += LINE_SPACING_TITLE;
  }

  // Divider
  const dividerY = TITLE_Y_START + titleBoxH + 24;
  const divGrad  = ctx.createLinearGradient(PAD, 0, W - PAD, 0);
  divGrad.addColorStop(0, accent);
  divGrad.addColorStop(1, hexToRgba(accent, 0.15));
  ctx.strokeStyle = divGrad;
  ctx.lineWidth = 4;
  ctx.lineCap = 'round';
  ctx.beginPath();
  ctx.moveTo(PAD, dividerY);
  ctx.lineTo(W - PAD, dividerY);
  ctx.stroke();

  // Elements
  let y = dividerY + 52;
  const elements  = scene.elements || [];
  const showCount = revealUpTo < 0 ? 0 : Math.min(revealUpTo + 1, elements.length);

  for (let i = 0; i < showCount; i++) {
    if (y > H - 260) break;
    y = drawElement(ctx, elements[i], y, accent, accent2);
  }

  // Footer
  ctx.strokeStyle = LINE_COLOR;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(PAD, FOOTER_Y - 44);
  ctx.lineTo(W - PAD, FOOTER_Y - 44);
  ctx.stroke();

  ctx.fillStyle = TEXT_MUTED;
  ctx.font = '28px Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('SmrAI Studio — Whiteboard Generator', W / 2, FOOTER_Y);
}

// ── Element renderers ─────────────────────────────────────────────────────────
function drawElement(ctx, el, y, accent, accent2) {
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';

  if (el.type === 'text') {
    ctx.fillStyle = TEXT_BODY;
    ctx.font = '46px Arial';
    const lines = wrapTextLines(ctx, el.content, W - PAD * 2, '46px Arial');
    for (const line of lines) {
      ctx.fillText(line, PAD, y);
      y += LINE_SPACING_BODY;
    }
    y += 16;

  } else if (el.type === 'bullet') {
    ctx.fillStyle = accent;
    ctx.beginPath();
    ctx.arc(PAD + 16, y + 24, 11, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = TEXT_BODY;
    ctx.font = '46px Arial';
    const lines = wrapTextLines(ctx, el.content, W - PAD * 2 - 52, '46px Arial');
    for (const line of lines) {
      ctx.fillText(line, PAD + 46, y);
      y += LINE_SPACING_BODY;
    }
    y += 14;

  } else if (el.type === 'equation') {
    const boxH = 96;
    ctx.fillStyle = '#f5f3ff';
    drawRoundRect(ctx, PAD, y, W - PAD * 2, boxH, 14);
    ctx.fillStyle = EQ_COLOR;
    ctx.font = 'bold italic 52px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(el.content, W / 2, y + boxH / 2);
    y += boxH + 28;

  } else if (el.type === 'highlight') {
    const color = el.color || accent;
    ctx.font = 'bold 46px Arial';
    const lines = wrapTextLines(ctx, el.content, W - PAD * 2 - 32, 'bold 46px Arial');
    const boxH  = lines.length * 60 + 44;
    ctx.fillStyle = hexToRgba(color, 0.15);
    drawRoundRect(ctx, PAD, y, W - PAD * 2, boxH, 14);
    ctx.fillStyle = color;
    ctx.fillRect(PAD, y, 7, boxH);
    ctx.fillStyle = TEXT_DARK;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    let hy = y + 22;
    for (const line of lines) {
      ctx.fillText(line, PAD + 26, hy);
      hy += 60;
    }
    y += boxH + 24;

  } else if (el.type === 'comparison') {
    const labelW = 220;
    const gap    = 12;
    const colW   = (W - PAD * 2 - labelW - gap * 2) / 2;
    const hdrH   = 68;
    const rowH   = 68;
    const rows   = el.rows || [];

    // Column headers
    ctx.fillStyle = accent;
    drawRoundRect(ctx, PAD + labelW + gap, y, colW, hdrH, 10);
    ctx.fillStyle = accent2;
    drawRoundRect(ctx, PAD + labelW + gap + colW + gap, y, colW, hdrH, 10);

    ctx.fillStyle = '#fff';
    ctx.font = 'bold 36px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(el.col1_header || 'Option A', PAD + labelW + gap + colW / 2, y + hdrH / 2);
    ctx.fillText(el.col2_header || 'Option B', PAD + labelW + gap + colW + gap + colW / 2, y + hdrH / 2);

    y += hdrH + 6;

    for (let r = 0; r < rows.length; r++) {
      const row  = rows[r];
      const rowY = y;
      if (r % 2 === 1) {
        ctx.fillStyle = '#f7f7f7';
        ctx.fillRect(PAD, rowY, W - PAD * 2, rowH);
      }
      ctx.fillStyle = TEXT_MUTED;
      ctx.font = '28px Arial';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(row.label || '', PAD + labelW - 8, rowY + rowH / 2);

      ctx.fillStyle = TEXT_DARK;
      ctx.font = 'bold 38px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(row.col1 || '', PAD + labelW + gap + colW / 2, rowY + rowH / 2);
      ctx.fillText(row.col2 || '', PAD + labelW + gap + colW + gap + colW / 2, rowY + rowH / 2);

      ctx.strokeStyle = LINE_COLOR;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(PAD, rowY + rowH);
      ctx.lineTo(W - PAD, rowY + rowH);
      ctx.stroke();

      y += rowH;
    }
    y += 26;
  }

  return y;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function wrapTextLines(ctx, text, maxWidth, font) {
  ctx.font = font;
  const words = text.split(' ');
  const lines = [];
  let line = '';
  for (const word of words) {
    const test = line ? line + ' ' + word : word;
    if (ctx.measureText(test).width > maxWidth && line) {
      lines.push(line);
      line = word;
    } else {
      line = test;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function drawRoundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.arcTo(x + w, y, x + w, y + r, r);
  ctx.lineTo(x + w, y + h - r);
  ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h);
  ctx.arcTo(x, y + h, x, y + h - r, r);
  ctx.lineTo(x, y + r);
  ctx.arcTo(x, y, x + r, y, r);
  ctx.closePath();
  ctx.fill();
}
