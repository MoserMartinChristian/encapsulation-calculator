#!/usr/bin/env node
// Inlines src/*.{css,js} into a single self-contained index.html (no CDN, no network).
'use strict';
const fs = require('fs');
const path = require('path');
const src = (f) => fs.readFileSync(path.join(__dirname, 'src', f), 'utf8');
let html = src('template.html');
html = html.replace(/\/\*INLINE:([\w.]+)\*\//g, (m, file) => {
  const content = src(file);
  if (/<\/script/i.test(content) || /<\/style/i.test(content)) throw new Error(file + ' contains a closing tag');
  return content;
});
if (/\b(src|href)=["']https?:/i.test(html.replace(/<a [^>]*>/g, ''))) throw new Error('external resource found');
fs.writeFileSync(path.join(__dirname, 'index.html'), html);
console.log('index.html written (' + (html.length / 1024).toFixed(1) + ' KiB)');
