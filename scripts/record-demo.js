#!/usr/bin/env node
// Records docs/demo.gif (+ demo.webm) and docs/screenshot.png with Playwright + ffmpeg.
// Usage: node scripts/record-demo.js   (needs playwright and ffmpeg)
'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname, '..');
const FILE = 'file://' + path.join(ROOT, 'index.html');
const OUT = path.join(ROOT, 'docs');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'encap-video-'));

// Playwright videos do not show the mouse pointer – draw one.
const CURSOR = `(() => { const c = document.createElement('div');
  c.style.cssText = 'position:fixed;z-index:9999;left:-40px;top:-40px;width:18px;height:18px;border-radius:50%;background:rgba(255,255,255,.92);border:2px solid #111;pointer-events:none;transform:translate(-50%,-50%);transition:width .1s,height .1s;box-shadow:0 2px 8px rgba(0,0,0,.5)';
  document.addEventListener('DOMContentLoaded', () => document.body.appendChild(c));
  addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
  addEventListener('mousedown', () => { c.style.width = c.style.height = '13px'; }, true);
  addEventListener('mouseup', () => { c.style.width = c.style.height = '18px'; }, true); })();`;

(async () => {
  const browser = await chromium.launch();

  // README screenshot
  const sctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: 'dark' });
  const sp = await sctx.newPage();
  await sp.goto(FILE + '#m=1500&s=eth_ipv4_esp.m-transport_gre_ipv4_tcp');
  await sp.waitForTimeout(900);
  await sp.screenshot({ path: path.join(OUT, 'screenshot.png') });
  await sctx.close();

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, colorScheme: 'dark', recordVideo: { dir: TMP, size: { width: 1280, height: 900 } } });
  await ctx.addInitScript(CURSOR);
  const p = await ctx.newPage();
  await p.goto(FILE + '#m=1500&s=');
  await p.waitForTimeout(700);
  const glide = (x, y, steps = 18) => p.mouse.move(x, y, { steps });
  const click = async (sel, wait) => {
    const b = await p.locator(sel).first().boundingBox();
    await glide(b.x + b.width / 2, b.y + b.height / 2, 14);
    await p.mouse.down(); await p.mouse.up();
    await p.waitForTimeout(wait);
  };
  async function drag(type) {
    const a = await p.locator(`.chip[data-type="${type}"]`).boundingBox();
    await glide(a.x + a.width / 2, a.y + a.height / 2, 14);
    await p.mouse.down();
    const cards = await p.$$('#stack .card');
    let b;
    if (cards.length) { const r = await cards[cards.length - 1].boundingBox(); b = { x: r.x + r.width / 2, y: r.y + r.height - 6 }; }
    else { const r = await p.locator('#stack-empty').boundingBox(); b = { x: r.x + r.width / 2, y: r.y + r.height / 2 }; }
    await glide(b.x, b.y, 22);
    await p.waitForTimeout(120);
    await p.mouse.up();
    await p.waitForTimeout(380);
  }
  for (const t of ['eth', 'ipv4', 'udp', 'vxlan', 'eth', 'ipv4']) await drag(t);
  await p.waitForTimeout(900);
  const f = await p.locator('#bytemap .fld >> nth=9').boundingBox();
  if (f) { await glide(f.x + f.width / 2, f.y + f.height / 2, 20); await p.waitForTimeout(1100); }
  for (const m of ['1600', '9000', '1500']) await click(`#mtu-presets button:text-is("${m}")`, 800);
  await click('[data-preset="wg-pppoe"]', 1300);
  await click('[data-preset="gre-ipsec"]', 1300);
  await click('#mode-r', 1300);
  await click('#btn-theme', 1500);
  const video = await p.video().path();
  await ctx.close();
  await browser.close();

  const gif = path.join(OUT, 'demo.gif');
  const pal = path.join(TMP, 'palette.png');
  const vf = 'fps=10,scale=760:-1:flags=lanczos';
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '0.4', '-i', video, '-vf', vf + ',palettegen=max_colors=128:stats_mode=diff', pal]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '0.4', '-i', video, '-i', pal, '-lavfi', vf + ' [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle', gif]);
  fs.copyFileSync(video, path.join(OUT, 'demo.webm'));
  // MP4 for LinkedIn (H.264)
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', video, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '22', '-movflags', '+faststart', path.join(OUT, 'demo.mp4')]);
  console.log('demo.gif', (fs.statSync(gif).size / 1024 / 1024).toFixed(2), 'MiB');
})();
