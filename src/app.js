/* Encapsulation Calculator – user interface. All maths lives in calc.js. */
(function () {
  'use strict';
  var C = window.EncapCalc, G = window.EncapConfig, I = window.EncapI18n;
  var $ = function (id) { return document.getElementById(id); };

  var HUES = { eth: 215, dot1q: 228, qinq: 242, macsec: 4, pppoe: 268, mpls: 286, ipv4: 165, ipv6: 145, srv6: 122,
               udp: 46, tcp: 30, gre: 335, vxlan: 314, geneve: 298, lisp: 255, esp: 18, wg: 190, payload: 220 };
  var GROUPS = [['l2', ['eth', 'dot1q', 'qinq', 'macsec']], ['shim', ['pppoe', 'mpls']], ['l3', ['ipv4', 'ipv6', 'srv6']],
                ['l4', ['udp', 'tcp']], ['tunnel', ['gre', 'vxlan', 'geneve', 'lisp']], ['sec', ['esp', 'wg']]];
  var MTU_PRESETS = [1500, 1492, 1600, 9000, 9216];
  var TARGET_PRESETS = [1280, 1400, 1500, 9000];
  var VENDORS = [['cisco', 'Cisco IOS'], ['linux', 'Linux'], ['mikrotik', 'MikroTik'], ['juniper', 'Juniper']];
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var uidSeq = 0;
  var state = { mtu: 1500, layers: [], mode: 'forward', target: 1500, probe: null, lang: 'en', vendor: 'cisco', preset: null };
  var last = null;          // last analysis result
  var cardEls = new Map();  // uid -> <li>
  var focusUid = null;

  // ------------------------------------------------------------------ utils
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function lookup(obj, path) { return path.split('.').reduce(function (o, k) { return o && o[k] !== undefined ? o[k] : undefined; }, obj); }
  function t(key, p) {
    var s = lookup(I.T[state.lang], key);
    if (s === undefined) s = lookup(I.T.en, key);
    if (s === undefined) s = key;
    if (p) s = String(s).replace(/\{(\w+)\}/g, function (m, k) { return p[k] !== undefined ? p[k] : m; });
    return s;
  }
  function el(tag, attrs, html) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'text') e.textContent = attrs[k];
      else if (k === 'style') e.style.cssText = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    if (html != null) e.innerHTML = html;
    return e;
  }
  function fmt(n) { return n == null ? '—' : String(n); }
  function storeGet(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } }
  function storeSet(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function announce(msg) { var l = $('live'); l.textContent = ''; setTimeout(function () { l.textContent = msg; }, 30); }
  var toastTimer;
  function toast(msg) { var x = $('toast'); x.textContent = msg; x.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(function () { x.classList.remove('show'); }, 2600); }
  function mkLayer(type, opts) { var n = C.normalizeLayer({ type: type, opts: opts || {} }); return { uid: ++uidSeq, type: n.type, opts: n.opts }; }
  function plain(layers) { return layers.map(function (l) { return { type: l.type, opts: l.opts }; }); }
  function layerName(l) { return C.LAYERS[l.type].name; }
  function refLabel(key) { return key.replace(/^RFC(\d+)$/, 'RFC $1').replace('IEEE-', 'IEEE ').replace('CISCO-MACSEC', 'Cisco MACsec').replace('WG-PAPER', 'WireGuard paper').replace('WG-LINUX', 'Linux WireGuard').replace('WG-QUICK', 'wg-quick'); }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).catch(function () { return fallbackCopy(text); });
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    var ta = el('textarea', { style: 'position:fixed;left:-9999px;top:0', 'aria-hidden': 'true' });
    ta.value = text; document.body.appendChild(ta); ta.select();
    var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta); return ok;
  }

  // ------------------------------------------------------------------ icons
  var ICON = {
    gear: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/></svg>',
    up: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 15l6-6 6 6"/></svg>',
    down: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>',
    x: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>'
  };

  // ------------------------------------------------------------------ analysis
  function compute() {
    var layers = plain(state.layers);
    var mtu = state.mtu, required = null;
    if (state.mode === 'reverse') {
      required = C.requiredUnderlay(layers, state.target);
      if (required != null) mtu = required;
    }
    var res = C.analyze({ mtu: mtu, layers: layers, probe: state.probe });
    res.required = required;
    res.reverse = state.mode === 'reverse';
    return res;
  }

  // ------------------------------------------------------------------ palette & presets
  function headerBytesLabel(type) {
    var def = C.LAYERS[type];
    var n = C.layerHeaderBytes({ type: type, opts: {} }, type === 'eth');
    if (type === 'esp') return '≥36';
    if (type === 'srv6') return '8+16n';
    if (type === 'mpls') return '4·n';
    return String(n) + (def.opts.length && type !== 'macsec' ? '+' : '');
  }
  function renderPalette() {
    var p = $('palette'); p.innerHTML = '';
    GROUPS.forEach(function (g) {
      var wrap = el('div', { class: 'palette-group', role: 'group', 'aria-label': t('groups.' + g[0]) });
      wrap.appendChild(el('h3', { text: t('groups.' + g[0]), 'aria-hidden': 'true' }));
      var items = el('div', { class: 'palette-items' });
      g[1].forEach(function (type) {
        var b = el('button', { type: 'button', class: 'chip', style: '--h:' + HUES[type], 'data-type': type,
          'aria-label': C.LAYERS[type].name + ' – ' + t('layerDesc.' + type) },
          '<span class="sw" aria-hidden="true"></span>' + esc(C.LAYERS[type].name) + '<span class="sz" aria-hidden="true">' + headerBytesLabel(type) + '</span>');
        b.title = t('layerDesc.' + type);
        b.addEventListener('click', function () {
          if (Date.now() < suppressClickUntil) return;
          addLayer(type, state.layers.length);
        });
        b.addEventListener('pointerdown', function (e) { startPress(e, { kind: 'new', type: type }); });
        items.appendChild(b);
      });
      wrap.appendChild(items);
      p.appendChild(wrap);
    });
  }
  function renderPresets() {
    var box = $('presets'); box.innerHTML = '';
    C.PRESETS.forEach(function (pr) {
      var dots = pr.layers.map(function (l) { var b = C.layerHeaderBytes(l, false); return '<i style="--h:' + HUES[l.type] + ';width:' + Math.max(4, Math.min(22, b / 1.6)) + 'px"></i>'; }).join('');
      var b = el('button', { type: 'button', class: 'preset', 'aria-pressed': String(state.preset === pr.id), 'data-preset': pr.id },
        '<strong>' + esc(pr.name) + '</strong><small>MTU ' + pr.mtu + '</small><span class="desc">' + esc(t('presetDesc.' + pr.id)) + '</span><span class="dots" aria-hidden="true">' + dots + '</span>');
      b.title = t('presetDesc.' + pr.id);
      b.addEventListener('click', function () { loadPreset(pr); });
      box.appendChild(b);
    });
  }
  function renderChips(boxId, list, current, onPick) {
    var box = $(boxId); box.innerHTML = '';
    list.forEach(function (v) {
      var b = el('button', { type: 'button', 'aria-pressed': String(v === current), text: String(v) });
      b.addEventListener('click', function () { onPick(v); });
      box.appendChild(b);
    });
  }

  // ------------------------------------------------------------------ actions
  function commit(mutate, msg, opts) {
    var first = rects();
    mutate();
    if (!(opts && opts.keepPreset)) state.preset = null;
    update();
    flip(first);
    if (msg) announce(msg);
  }
  function addLayer(type, index) {
    var L = mkLayer(type);
    commit(function () { state.layers.splice(index, 0, L); }, t('added', { layer: C.LAYERS[type].name, pos: index + 1, n: state.layers.length + 1 }));
    return L;
  }
  function moveLayer(uid, to) {
    var from = indexOf(uid); if (from < 0) return;
    to = Math.max(0, Math.min(state.layers.length - 1, to));
    if (from === to) return;
    var L = state.layers[from];
    focusUid = document.activeElement && document.activeElement.closest && document.activeElement.closest('.card') ? uid : focusUid;
    commit(function () { state.layers.splice(from, 1); state.layers.splice(to, 0, L); }, t('moved', { layer: layerName(L), pos: to + 1, n: state.layers.length }));
  }
  function removeLayer(uid, focusNext) {
    var i = indexOf(uid); if (i < 0) return;
    var L = state.layers[i], card = cardEls.get(uid);
    var nextUid = focusNext ? (state.layers[i + 1] || state.layers[i - 1] || {}).uid : null;
    var go = function () {
      commit(function () { state.layers.splice(i, 1); }, t('removed', { layer: layerName(L) }));
      if (nextUid && cardEls.get(nextUid)) cardEls.get(nextUid).focus();
    };
    if (card && !reduceMotion) { card.classList.add('leave'); setTimeout(go, 170); } else go();
  }
  function setOpt(uid, k, v) {
    var L = state.layers[indexOf(uid)]; if (!L) return;
    var o = Object.assign({}, L.opts); o[k] = v;
    L.opts = C.normalizeLayer({ type: L.type, opts: o }).opts;
    state.preset = null;
    update();
  }
  function loadPreset(pr) {
    commit(function () {
      state.layers = pr.layers.map(function (l) { return mkLayer(l.type, l.opts); });
      state.mtu = pr.mtu; state.probe = null; state.mode = 'forward'; state.preset = pr.id;
    }, t('presetLoaded', { name: pr.name }), { keepPreset: true });
  }
  function indexOf(uid) { for (var i = 0; i < state.layers.length; i++) if (state.layers[i].uid === uid) return i; return -1; }

  // ------------------------------------------------------------------ FLIP animation
  function rects() {
    var m = new Map();
    cardEls.forEach(function (c, uid) { m.set(uid, c.getBoundingClientRect()); });
    return m;
  }
  function flip(first) {
    if (reduceMotion) return;
    var fresh = 0;
    state.layers.forEach(function (L) {
      var c = cardEls.get(L.uid); if (!c) return;
      var a = first.get(L.uid);
      if (!a) {
        c.classList.remove('enter'); void c.offsetWidth;
        c.style.animationDelay = (fresh++ * 45) + 'ms';
        c.classList.add('enter');
        return;
      }
      var b = c.getBoundingClientRect(), dy = a.top - b.top;
      if (Math.abs(dy) < 1) return;
      c.style.transition = 'none';
      c.style.transform = 'translateY(' + dy + 'px)';
      requestAnimationFrame(function () {
        c.style.transition = 'transform .38s cubic-bezier(.2,.8,.2,1)';
        c.style.transform = '';
      });
    });
  }

  // ------------------------------------------------------------------ stack cards
  function optLabel(type, k) {
    var specific = t('opt.' + k + '_' + type);
    return specific.indexOf('opt.') === 0 ? t('opt.' + k) : specific;
  }
  function optValueLabel(type, k, v) {
    if (type === 'esp') {
      if (k === 'c') return C.ESP_CIPHERS[v].label;
      if (k === 'a') return C.ESP_INTEG[v].label + ' (' + C.ESP_INTEG[v].icv + ' B)';
      if (k === 'i') return v + ' B';
      if (k === 'b') return v + ' bit';
      if (k === 'm') return t('opt.' + v);
    }
    return String(v);
  }
  function summaryLine(L, idx, res) {
    var o = L.opts, s = [];
    switch (L.type) {
      case 'macsec': s.push(o.sci ? 'SecTAG 16 + ICV 16' : 'SecTAG 8 + ICV 16'); break;
      case 'mpls': s.push(o.n + ' label' + (o.n > 1 ? 's' : '')); break;
      case 'ipv4': s.push(o.o ? o.o + ' B options' : t('noOpts')); break;
      case 'srv6': s.push(o.n + ' SID' + (o.n > 1 ? 's' : '') + (o.r ? ' · reduced' : '')); break;
      case 'tcp': s.push(o.ts ? 'Timestamps' : t('noOpts')); break;
      case 'gre': if (o.c) s.push('Checksum'); if (o.k) s.push('Key'); if (o.s) s.push('Seq'); if (!s.length) s.push(t('noOpts')); break;
      case 'geneve': s.push(o.o + ' B options'); break;
      case 'esp': {
        s.push(t('opt.' + o.m)); s.push(C.ESP_CIPHERS[o.c].label.replace('AES-', 'AES-' + (o.c === 'chacha20' ? '' : o.b + '-')).replace('AES--', 'AES-'));
        if (o.c === 'aes-cbc') s.push(C.ESP_INTEG[o.a].label); else s.push('ICV ' + C.espParams(o).icv);
        if (o.n) s.push('NAT-T');
        var d = res.detail[idx]; if (d && d.pad) s.push('pad ' + d.pad);
        break;
      }
      case 'wg': {
        var outer = null; for (var j = idx - 1; j >= 0; j--) if (state.layers[j].type === 'ipv4' || state.layers[j].type === 'ipv6') { outer = C.LAYERS[state.layers[j].type].name; break; }
        s.push(t('opt.outerFrom', { v: outer || '—' }));
        var dw = res.detail[idx]; if (dw && dw.pad) s.push('pad ' + dw.pad);
        break;
      }
      case 'eth': s.push(idx < res.l2len ? 'DA · SA · Type · FCS' : 'inner, no FCS'); break;
      default: s.push(t('groups.' + C.LAYERS[L.type].group));
    }
    return s.join(' · ');
  }
  function buildOpts(L, box) {
    var def = C.LAYERS[L.type];
    def.opts.forEach(function (op) {
      var id = 'o' + L.uid + op.k;
      var row = el('div', { class: 'opt', 'data-k': op.k });
      var lab = el('label', { for: id, text: optLabel(L.type, op.k) });
      var ctl;
      if (op.type === 'bool') {
        ctl = el('input', { type: 'checkbox', id: id });
        ctl.checked = !!L.opts[op.k];
        ctl.addEventListener('change', function () { setOpt(L.uid, op.k, ctl.checked ? 1 : 0); });
      } else if (op.type === 'int') {
        ctl = el('input', { type: 'number', id: id, min: op.min, max: op.max, step: op.step, inputmode: 'numeric' });
        ctl.value = L.opts[op.k];
        ctl.addEventListener('change', function () { setOpt(L.uid, op.k, ctl.value); ctl.value = state.layers[indexOf(L.uid)].opts[op.k]; });
      } else {
        ctl = el('select', { id: id });
        op.values.forEach(function (v) {
          var o = el('option', { value: String(v), text: optValueLabel(L.type, op.k, v) });
          if (String(v) === String(L.opts[op.k])) o.selected = true;
          ctl.appendChild(o);
        });
        ctl.addEventListener('change', function () { setOpt(L.uid, op.k, ctl.value); });
      }
      row.appendChild(lab); row.appendChild(ctl); box.appendChild(row);
    });
  }
  function createCard(L) {
    var c = el('li', { class: 'card', tabindex: '0', 'data-uid': L.uid, style: '--h:' + HUES[L.type] });
    var hasOpts = C.LAYERS[L.type].opts.length > 0;
    c.innerHTML =
      '<button type="button" class="handle" tabindex="-1" aria-hidden="true">⠿</button>' +
      '<div class="card-main"><div class="card-title"><strong>' + esc(layerName(L)) + '</strong><span class="card-bytes"></span><span class="card-tag"></span></div><div class="card-sub"></div></div>' +
      '<div class="card-actions">' +
        (hasOpts ? '<button type="button" class="b-opt" aria-expanded="false" aria-controls="opts' + L.uid + '">' + ICON.gear + '</button>' : '') +
        '<button type="button" class="b-up">' + ICON.up + '</button><button type="button" class="b-down">' + ICON.down + '</button>' +
        '<button type="button" class="rm">' + ICON.x + '</button></div>' +
      '<div class="refs"></div>' +
      (hasOpts ? '<div class="card-opts" id="opts' + L.uid + '" hidden></div>' : '');
    if (hasOpts) {
      buildOpts(L, c.querySelector('.card-opts'));
      var bo = c.querySelector('.b-opt');
      bo.addEventListener('click', function () {
        var box = c.querySelector('.card-opts'); var open = box.hidden;
        box.hidden = !open; bo.setAttribute('aria-expanded', String(open));
        if (open) { var f = box.querySelector('input,select'); if (f) f.focus(); }
      });
    }
    c.querySelector('.b-up').addEventListener('click', function () { moveLayer(L.uid, indexOf(L.uid) - 1); });
    c.querySelector('.b-down').addEventListener('click', function () { moveLayer(L.uid, indexOf(L.uid) + 1); });
    c.querySelector('.rm').addEventListener('click', function () { removeLayer(L.uid, true); });
    c.querySelector('.handle').addEventListener('pointerdown', function (e) { startPress(e, { kind: 'move', uid: L.uid }); });
    c.addEventListener('keydown', function (e) {
      if (e.target !== c) return;
      var i = indexOf(L.uid);
      if ((e.altKey || e.ctrlKey || e.metaKey) && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
        e.preventDefault(); focusUid = L.uid; moveLayer(L.uid, i + (e.key === 'ArrowUp' ? -1 : 1));
      } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault(); var n = state.layers[i + (e.key === 'ArrowUp' ? -1 : 1)]; if (n) cardEls.get(n.uid).focus();
      } else if (e.key === 'Delete' || e.key === 'Backspace') {
        e.preventDefault(); removeLayer(L.uid, true);
      } else if ((e.key === 'Enter' || e.key === ' ') && hasOpts) {
        e.preventDefault(); c.querySelector('.b-opt').click();
      }
    });
    return c;
  }
  function cardRefs(L) {
    if (L.type === 'esp') {
      var r = ['RFC4303', C.ESP_CIPHERS[L.opts.c].ref];
      if (L.opts.c === 'aes-cbc') r.push(C.ESP_INTEG[L.opts.a].ref);
      if (L.opts.n) r.push('RFC3948');
      return r;
    }
    if (L.type === 'wg') return ['WG-PAPER', 'WG-LINUX'];
    return C.LAYERS[L.type].refs.slice(0, 2);
  }
  function updateCard(c, L, i, res) {
    var refs = cardRefs(L), sig = refs.join(',');
    var rb = c.querySelector('.refs');
    if (rb._sig !== sig) {
      rb._sig = sig;
      rb.innerHTML = refs.map(function (r) { return '<a href="' + esc(C.REFS[r].u) + '" target="_blank" rel="noopener noreferrer" tabindex="-1" title="' + esc(C.REFS[r].t) + '">' + esc(refLabel(r)) + '</a>'; }).join('');
    }
    var n = state.layers.length, d = res.detail[i];
    var outer = i < res.l2len;
    var bytes = d ? d.h + d.t : 0;
    c.querySelector('.card-bytes').textContent = bytes + ' B';
    c.querySelector('.card-tag').textContent = outer ? t('outerL2') : (res.anchor >= 0 && i > res.anchor ? 'payload' : (i === res.anchor ? t('innerTag') : t('inMtu')));
    c.querySelector('.card-sub').textContent = summaryLine(L, i, res);
    c.classList.toggle('frame-only', outer);
    var hasErr = res.warnings.some(function (w) { return w.level === 'error' && w.p.i === i; });
    c.classList.toggle('has-error', hasErr);
    c.setAttribute('aria-label', layerName(L) + ', ' + bytes + ' B, ' + t('position', { pos: i + 1, n: n }) + (outer ? ', ' + t('outerL2') : ''));
    c.querySelector('.b-up').setAttribute('aria-label', t('moveUp') + ': ' + layerName(L)); c.querySelector('.b-up').title = t('moveUp');
    c.querySelector('.b-down').setAttribute('aria-label', t('moveDown') + ': ' + layerName(L)); c.querySelector('.b-down').title = t('moveDown');
    c.querySelector('.rm').setAttribute('aria-label', t('remove') + ': ' + layerName(L)); c.querySelector('.rm').title = t('remove');
    c.querySelector('.b-up').disabled = i === 0; c.querySelector('.b-down').disabled = i === n - 1;
    var bo = c.querySelector('.b-opt'); if (bo) { bo.setAttribute('aria-label', t('options') + ': ' + layerName(L)); bo.title = t('options'); }
    if (L.type === 'esp') {
      var box = c.querySelector('.card-opts');
      box.querySelector('[data-k="i"]').hidden = L.opts.c !== 'aes-gcm';
      box.querySelector('[data-k="a"]').hidden = L.opts.c !== 'aes-cbc';
      box.querySelector('[data-k="b"]').hidden = L.opts.c === 'chacha20';
    }
    var box2 = c.querySelector('.card-opts');
    if (box2) box2.querySelectorAll('.opt').forEach(function (row) {
      var k = row.getAttribute('data-k'); row.querySelector('label').textContent = optLabel(L.type, k);
      var ctl = row.querySelector('input,select');
      if (ctl.tagName === 'SELECT') Array.prototype.forEach.call(ctl.options, function (o) { var v = o.value; var op = C.LAYERS[L.type].opts.filter(function (x) { return x.k === k; })[0]; var real = op.values.filter(function (x) { return String(x) === v; })[0]; o.textContent = optValueLabel(L.type, k, real); });
    });
  }
  function renderStack(res) {
    var list = $('stack');
    var keep = new Set(state.layers.map(function (l) { return l.uid; }));
    cardEls.forEach(function (c, uid) { if (!keep.has(uid)) { c.remove(); cardEls.delete(uid); } });
    state.layers.forEach(function (L, i) {
      var c = cardEls.get(L.uid);
      if (!c) { c = createCard(L); cardEls.set(L.uid, c); }
      if (list.children[i] !== c) list.insertBefore(c, list.children[i] || null);
      updateCard(c, L, i, res);
    });
    $('stack-empty').hidden = state.layers.length > 0;
    if (focusUid && cardEls.get(focusUid)) { cardEls.get(focusUid).focus({ preventScroll: false }); focusUid = null; }
  }

  // ------------------------------------------------------------------ results
  var kpiEls = {};
  function kpi(id, primary) {
    if (kpiEls[id]) return kpiEls[id];
    var k = el('div', { class: 'kpi' + (primary ? ' primary' : ''), id: 'kpi-' + id }, '<div class="k"></div><div class="v"><span class="num">0</span><small></small></div><div class="s"></div>');
    k._v = 0; kpiEls[id] = k; return k;
  }
  function tween(k, to, suffix) {
    var numEl = k.querySelector('.num');
    k.querySelector('.v small').textContent = suffix || '';
    if (to == null || typeof to !== 'number' || !isFinite(to)) { numEl.textContent = to == null ? '—' : String(to); k._v = 0; return; }
    var from = k._v || 0; k._v = to;
    if (reduceMotion || from === to || Math.abs(to - from) > 20000) { numEl.textContent = String(to); return; }
    k.classList.remove('pulse'); void k.offsetWidth; k.classList.add('pulse');
    var t0 = performance.now(), dur = 420;
    var step = function (now) {
      var p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      numEl.textContent = String(Math.round(from + (to - from) * e));
      if (p < 1 && k._v === to) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  function renderKpis(res) {
    var box = $('kpis');
    var order = res.reverse ? ['req', 'inner', 'over', 'mss4', 'mss6', 'frame'] : ['inner', 'over', 'mss4', 'mss6', 'frame'];
    var want = order.map(function (id) { return kpi(id, id === (res.reverse ? 'req' : 'inner')); });
    want.forEach(function (k, i) { k.classList.toggle('primary', i === 0); if (box.children[i] !== k) box.insertBefore(k, box.children[i] || null); });
    while (box.children.length > want.length) box.removeChild(box.lastChild);
    var bad = res.innerMTU <= 0 || (res.reverse && res.required == null);
    function set(id, label, val, suf, sub, isBad) {
      var k = kpiEls[id]; k.querySelector('.k').textContent = label; tween(k, val, suf); k.querySelector('.s').textContent = sub; k.classList.toggle('bad', !!isBad);
    }
    if (res.reverse) set('req', t('required'), res.required == null ? t('impossible') : res.required, res.required == null ? '' : 'B', t('requiredSub', { t: state.target }), res.required == null);
    set('inner', t('innerMtu'), bad ? null : res.innerMTU, 'B', t('innerMtuSub') + (res.innerFamily ? ' (' + C.LAYERS[res.innerFamily].name + ')' : ''), res.innerMTU <= 0);
    set('over', t('overhead'), bad ? null : res.overhead, 'B', bad ? '' : res.overheadPct.toFixed(1) + ' % · +' + res.l2Overhead + ' B L2', false);
    set('mss4', t('mssV4'), bad || res.mssV4 <= 0 ? null : res.mssV4, 'B', t('mssSub', { n: res.innerMTU - res.mssV4 }), false);
    set('mss6', t('mssV6'), bad || res.mssV6 <= 0 ? null : res.mssV6, 'B', res.innerMTU < 1280 ? '< 1280 · IPv6 ✗' : t('mssSub', { n: 60 }), res.innerMTU < 1280 && res.innerMTU > 0);
    set('frame', t('frame'), res.frameSize, res.frameSize == null ? '' : 'B', res.frameSize == null ? t('noFrame') : t('frameSub', { w: res.wireSize }), false);
    kpiEls.mss4.classList.toggle('primary', !res.reverse && res.innerFamily === 'ipv4' && false);
    var tn = $('ts-note');
    if (res.tsPayload != null && !bad) { tn.hidden = false; tn.textContent = t('tsNote', { n: res.tsPayload }); } else tn.hidden = true;
    // mobile summary bar
    var errs = res.warnings.filter(function (w) { return w.level === 'error'; }).length;
    $('summary-bar').innerHTML = '<span>' + esc(t('innerMtu')) + ' <b>' + fmt(bad ? null : res.innerMTU) + '</b></span><span>MSS ' + fmt(bad ? null : res.mssV4) + ' / ' + fmt(bad || res.innerMTU < 1280 ? null : res.mssV6) + '</span>' + (errs ? '<span class="w">' + errs + ' ✗</span>' : '');
  }

  function renderWarnings(res) {
    var ul = $('warnings'); ul.innerHTML = '';
    var list = res.warnings.slice().sort(function (a, b) { var o = { error: 0, warn: 1, info: 2 }; return o[a.level] - o[b.level]; });
    if (!list.some(function (w) { return w.level === 'error' || w.level === 'warn'; })) {
      ul.appendChild(el('li', { class: 'ok' }, '<span class="ic" aria-hidden="true">✓</span><span>' + esc(t('allGood')) + '</span>'));
    }
    list.forEach(function (w) {
      var p = Object.assign({}, w.p); if (p.i != null) p.pos = p.i + 1;
      var icon = { error: '!', warn: '▲', info: 'i' }[w.level];
      var sr = { error: 'Error', warn: 'Warning', info: 'Info' }[w.level];
      ul.appendChild(el('li', { class: w.level, 'data-code': w.code }, '<span class="ic" aria-hidden="true">' + icon + '</span><span><span class="sr-only">' + sr + ': </span>' + esc(t('warn.' + w.code, p)) + '</span>'));
    });
  }

  // ------------------------------------------------------------------ byte layout
  var tipData = new WeakMap();
  var segEls = new Map(), fldEls = new Map();
  function layerUidAt(i) { return i >= 0 && state.layers[i] ? state.layers[i].uid : 'p'; }

  function renderFrameBar(res) {
    var bar = $('framebar'), total = res.layout.total || 1;
    var segs = [];
    res.layout.fields.forEach(function (f) {
      var key = f.payload ? 'payload' : layerUidAt(f.layer) + (f.trailer ? 't' : 'h');
      var lastS = segs[segs.length - 1];
      if (lastS && lastS.key === key) { lastS.bytes += f.bytes; lastS.enc = lastS.enc && f.enc; }
      else segs.push({ key: key, bytes: f.bytes, type: f.type, layer: f.layer, enc: f.enc, payload: !!f.payload, trailer: !!f.trailer });
    });
    var seen = new Set();
    var width = bar.clientWidth || 600;
    segs.forEach(function (s, i) {
      seen.add(s.key);
      var e = segEls.get(s.key);
      if (!e) { e = el('div', { class: 'seg-b' }, '<span></span>'); e.style.width = '0%'; segEls.set(s.key, e); }
      if (bar.children[i] !== e) bar.insertBefore(e, bar.children[i] || null);
      e.className = 'seg-b' + (s.payload ? ' payload' : '') + (s.enc ? ' enc' : '');
      e.style.setProperty('--h', HUES[s.type] || 220);
      var pct = s.bytes / total * 100;
      requestAnimationFrame(function () { e.style.width = pct + '%'; });
      var name = s.payload ? 'Payload' : C.LAYERS[s.type].name + (s.trailer ? ' trailer' : '');
      e.querySelector('span').textContent = (pct / 100 * width > 70) ? name + ' ' + s.bytes + ' B' : (pct / 100 * width > 26 ? String(s.bytes) : '');
      tipData.set(e, { title: name, meta: s.bytes + ' B · ' + pct.toFixed(1) + ' %', desc: s.payload ? I.FIELDS.payload[state.lang === 'de' ? 1 : 0] : t('layerDesc.' + s.type) });
    });
    segEls.forEach(function (e, k) { if (!seen.has(k)) { e.remove(); segEls.delete(k); } });
    bar.setAttribute('aria-label', 'Frame ' + res.layout.total + ' B: ' + segs.map(function (s) { return (s.payload ? 'payload' : C.LAYERS[s.type].name) + ' ' + s.bytes; }).join(', '));
    // ruler
    var ruler = $('ruler'); ruler.innerHTML = '';
    var stepB = [100, 250, 500, 1000, 2000, 2500, 5000, 10000].filter(function (s) { return total / s <= 6; })[0] || 20000;
    for (var b = 0; b < total - stepB * 0.35; b += stepB) ruler.appendChild(el('span', { style: 'left:' + (b / total * 100) + '%', text: String(b) }));
    ruler.appendChild(el('span', { style: 'left:100%', text: total + ' B' }));
  }

  function renderByteMap(res) {
    var map = $('bytemap');
    var w = map.clientWidth || 600;
    var u = w >= 640 ? 8 : (w >= 420 ? 6 : 5);
    $('h-bytemap').textContent = t('layoutHeaders', { u: u });
    var seen = new Set(), counters = {};
    var lang = state.lang === 'de' ? 1 : 0;
    var fields = res.layout.fields;
    var idx = 0;
    fields.forEach(function (f, i) {
      var base = f.payload ? 'payload' : layerUidAt(f.layer) + (f.trailer ? 't' : 'h');
      counters[base] = (counters[base] || 0) + 1;
      var key = base + ':' + counters[base];
      seen.add(key);
      var e = fldEls.get(key);
      if (!e) { e = el('div', { class: 'fld', role: 'listitem' }, '<span></span>'); e.style.width = '0px'; fldEls.set(key, e); }
      if (map.children[idx] !== e) map.insertBefore(e, map.children[idx] || null);
      idx++;
      var prev = fields[i - 1], next = fields[i + 1];
      var first = !prev || prev.layer !== f.layer || !!prev.trailer !== !!f.trailer || prev.payload;
      var lastF = !next || next.layer !== f.layer || !!next.trailer !== !!f.trailer || next.payload;
      e.className = 'fld' + (f.payload ? ' payload' : '') + (f.enc ? ' enc' : '') + (f.frameOnly ? ' frame-only' : '') + (first ? ' first' : '') + (lastF ? ' last' : '');
      e.id = 'fld-' + i;
      e.style.setProperty('--h', HUES[f.type] || 220);
      var lname = f.payload ? 'Payload' : C.LAYERS[f.type].name;
      var span = e.querySelector('span');
      if (f.payload) { e.style.width = ''; span.textContent = t('payloadNotToScale', { n: f.bytes }); }
      else {
        var px = f.bytes * u;
        requestAnimationFrame(function () { e.style.width = px + 'px'; });
        var short = f.name.replace(/ Address$/, '').replace(/^Destination/, 'Dst').replace(/^Source/, 'Src');
        span.textContent = px >= short.length * 6.3 + 6 ? short : (px >= 16 ? String(f.bytes) : '');
      }
      var desc = (I.FIELDS[f.key] || ['', ''])[lang];
      var refs = f.payload ? '' : C.LAYERS[f.type].refs.map(refLabel).join(', ');
      tipData.set(e, { title: lname + ' · ' + f.name, meta: f.bytes + ' B · offset ' + f.offset + (f.enc ? ' · ' + t('encrypted') : '') + (f.frameOnly ? ' · ' + t('outerL2') : ''), desc: desc, ref: refs });
      e.setAttribute('aria-label', t('fieldAria', { layer: lname, field: f.name, bytes: f.bytes, off: f.offset }) + (f.enc ? ', ' + t('encrypted') : ''));
    });
    fldEls.forEach(function (e, k) { if (!seen.has(k)) { e.remove(); fldEls.delete(k); } });
    if (activeField >= fields.length) activeField = fields.length - 1;
    // table
    var rows = fields.map(function (f) {
      return '<tr><td class="n">' + f.offset + '</td><td class="n">' + f.bytes + '</td><td><span class="sw" style="--h:' + (HUES[f.type] || 220) + '"></span>' + esc(f.payload ? 'Payload' : C.LAYERS[f.type].name) + '</td><td>' + esc(f.name) + (f.enc ? ' 🔒' : '') + '</td></tr>';
    }).join('');
    $('fieldtable').innerHTML = '<thead><tr><th scope="col">' + esc(t('tOffset')) + '</th><th scope="col">' + esc(t('tBytes')) + '</th><th scope="col">' + esc(t('tLayer')) + '</th><th scope="col">' + esc(t('tField')) + '</th></tr></thead><tbody>' + rows + '</tbody>';
  }

  function renderProbe(res) {
    var r = $('probe'), max = Math.max(0, res.innerMTU);
    r.max = String(max); r.disabled = max <= 0;
    r.value = String(state.probe == null ? max : Math.min(state.probe, max));
    $('probe-out').textContent = (state.probe == null ? max : Math.min(state.probe, max)) + ' B' + (state.probe == null ? ' (' + t('probeMax') + ')' : '');
  }

  // tooltips
  var tipEl, activeField = -1;
  function showTip(target, x, y) {
    var d = tipData.get(target); if (!d) return hideTip();
    tipEl.innerHTML = '<b>' + esc(d.title) + '</b><div class="tt-meta">' + esc(d.meta) + '</div>' + (d.desc ? '<div>' + esc(d.desc) + '</div>' : '') + (d.ref ? '<div class="tt-ref">' + esc(d.ref) + '</div>' : '');
    tipEl.hidden = false;
    var r = tipEl.getBoundingClientRect(), vw = window.innerWidth, vh = window.innerHeight;
    var left = Math.min(vw - r.width - 8, Math.max(8, x - r.width / 2)), top = y - r.height - 14;
    if (top < 8) top = y + 22;
    if (top + r.height > vh - 8) top = vh - r.height - 8;
    tipEl.style.left = left + 'px'; tipEl.style.top = top + 'px';
  }
  function hideTip() { if (tipEl) tipEl.hidden = true; }
  function initTooltips() {
    tipEl = $('tooltip');
    ['framebar', 'bytemap'].forEach(function (id) {
      var host = $(id);
      host.addEventListener('pointermove', function (e) {
        var tEl = e.target.closest('.fld, .seg-b'); if (!tEl || (drag && drag.active)) return hideTip();
        showTip(tEl, e.clientX, e.clientY);
      });
      host.addEventListener('pointerleave', hideTip);
    });
    var bm = $('bytemap');
    bm.addEventListener('keydown', function (e) {
      var n = bm.children.length; if (!n) return;
      var k = e.key, i = activeField;
      if (k === 'ArrowRight' || k === 'ArrowDown') i = Math.min(n - 1, i + 1);
      else if (k === 'ArrowLeft' || k === 'ArrowUp') i = Math.max(0, i - 1);
      else if (k === 'Home') i = 0; else if (k === 'End') i = n - 1;
      else if (k === 'Escape') { hideTip(); return; } else return;
      e.preventDefault(); setActiveField(i);
    });
    bm.addEventListener('focus', function () { setActiveField(activeField < 0 ? 0 : activeField); });
    bm.addEventListener('blur', function () { hideTip(); var a = bm.querySelector('.fld.active'); if (a) a.classList.remove('active'); });
    window.addEventListener('scroll', hideTip, { passive: true });
  }
  function setActiveField(i) {
    var bm = $('bytemap'), prev = bm.querySelector('.fld.active');
    if (prev) prev.classList.remove('active');
    var f = bm.children[i]; if (!f) return;
    activeField = i; f.classList.add('active');
    bm.setAttribute('aria-activedescendant', f.id);
    var r = f.getBoundingClientRect(); showTip(f, r.left + r.width / 2, r.top);
  }

  // ------------------------------------------------------------------ config & sources
  function highlight(code) {
    return code.split('\n').map(function (line) {
      var m = line.match(/^(\s*)([!#].*)$/);
      if (m) return m[1] + '<span class="cm">' + esc(m[2]) + '</span>';
      var cmt = '', i = line.search(/\s{2,}[!#] /);
      if (i > 0) { cmt = '<span class="cm">' + esc(line.slice(i)) + '</span>'; line = line.slice(0, i); }
      return esc(line).replace(/(^|[\s=])(\d{3,5})(?=$|[\s-])/g, '$1<span class="num">$2</span>') + cmt;
    }).join('\n');
  }
  var cfgText = '';
  function renderConfig(res) {
    var tabs = $('cfg-tabs');
    if (!tabs.children.length) {
      VENDORS.forEach(function (v, i) {
        var b = el('button', { type: 'button', role: 'tab', id: 'tab-' + v[0], 'aria-controls': 'cfg-panel', text: v[1] });
        b.addEventListener('click', function () { state.vendor = v[0]; renderConfig(last); });
        b.addEventListener('keydown', function (e) {
          if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
          var j = (i + (e.key === 'ArrowRight' ? 1 : VENDORS.length - 1)) % VENDORS.length;
          state.vendor = VENDORS[j][0]; renderConfig(last); $('tab-' + state.vendor).focus();
        });
        tabs.appendChild(b);
      });
    }
    VENDORS.forEach(function (v) { var b = $('tab-' + v[0]); var sel = v[0] === state.vendor; b.setAttribute('aria-selected', String(sel)); b.tabIndex = sel ? 0 : -1; });
    $('cfg-panel').setAttribute('aria-labelledby', 'tab-' + state.vendor);
    var all = G.generate(res, { reverse: res.reverse && res.required != null });
    cfgText = all[state.vendor];
    $('cfg-code').innerHTML = highlight(cfgText);
    $('cfg-refs').innerHTML = G.CONFIG_REFS[state.vendor].map(function (r) { return '<li><a href="' + esc(r.u) + '" target="_blank" rel="noopener noreferrer">' + esc(r.t) + '</a></li>'; }).join('');
  }
  function renderSources() {
    var keys = [];
    state.layers.forEach(function (l) { C.LAYERS[l.type].refs.forEach(function (r) { if (keys.indexOf(r) < 0) keys.push(r); }); });
    ['RFC879', 'IEEE-802.3'].forEach(function (r) { if (keys.indexOf(r) < 0) keys.push(r); });
    $('sources').innerHTML = keys.map(function (k) { var r = C.REFS[k]; return '<li><b>' + esc(refLabel(k)) + '</b> – <a href="' + esc(r.u) + '" target="_blank" rel="noopener noreferrer">' + esc(r.t) + '</a></li>'; }).join('');
  }

  // ------------------------------------------------------------------ URL state
  function encode() {
    return C.encodeState({ mtu: state.mtu, layers: plain(state.layers), mode: state.mode, target: state.target, probe: state.probe, lang: state.lang });
  }
  var lastHash = '';
  function writeHash() {
    var h = encode();
    if (h !== lastHash) { lastHash = h; try { history.replaceState(null, '', h); } catch (e) { /* file:// in some browsers */ try { location.hash = h; } catch (e2) { /* ignore */ } } }
  }
  function readHash(hash) {
    var s = C.decodeState(hash);
    if (!s) return false;
    state.mtu = s.mtu; state.mode = s.mode; state.target = s.target; state.probe = s.probe;
    if (s.lang) state.lang = s.lang;
    state.layers = s.layers.map(function (l) { return mkLayer(l.type, l.opts); });
    state.preset = null;
    return true;
  }

  // ------------------------------------------------------------------ main update
  function update() {
    var res = compute();
    last = res;
    // inputs
    $('mode-f').setAttribute('aria-pressed', String(state.mode === 'forward'));
    $('mode-r').setAttribute('aria-pressed', String(state.mode === 'reverse'));
    $('row-underlay').hidden = state.mode === 'reverse';
    $('row-target').hidden = state.mode !== 'reverse';
    if (document.activeElement !== $('mtu')) $('mtu').value = state.mtu;
    if (document.activeElement !== $('target')) $('target').value = state.target;
    renderChips('mtu-presets', MTU_PRESETS, state.mtu, function (v) { state.mtu = v; state.probe = null; update(); });
    renderChips('target-presets', TARGET_PRESETS, state.target, function (v) { state.target = v; state.probe = null; update(); });
    document.querySelectorAll('.preset').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-preset') === state.preset)); });
    renderStack(res);
    renderKpis(res);
    renderWarnings(res);
    renderFrameBar(res);
    renderByteMap(res);
    renderProbe(res);
    renderConfig(res);
    renderSources();
    writeHash();
  }

  function applyI18n() {
    document.documentElement.lang = state.lang;
    document.querySelectorAll('[data-i18n]').forEach(function (e) { e.textContent = t(e.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-aria]').forEach(function (e) { e.setAttribute('aria-label', t(e.getAttribute('data-i18n-aria'))); });
    $('lang-en').setAttribute('aria-pressed', String(state.lang === 'en'));
    $('lang-de').setAttribute('aria-pressed', String(state.lang === 'de'));
    $('btn-theme').title = t('theme');
    document.querySelector('.wire-label span').textContent = state.lang === 'de' ? 'außen · zuerst auf dem Kabel' : 'outer · first on the wire';
    document.querySelector('.wire-label.end span').textContent = state.lang === 'de' ? 'innen · Payload' : 'inner · payload';
    renderPalette();
    renderPresets();
  }
  function setLang(l) { state.lang = l; storeSet('encap-lang', l); applyI18n(); update(); }

  // ------------------------------------------------------------------ theme
  function effectiveTheme() {
    var a = document.documentElement.getAttribute('data-theme');
    if (a === 'dark' || a === 'light') return a;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  function setTheme(th) { document.documentElement.setAttribute('data-theme', th); storeSet('encap-theme', th); }

  // ------------------------------------------------------------------ drag & drop (pointer events: mouse, pen, touch)
  var drag = null, suppressClickUntil = 0, ghost = null, indicator = null;
  function startPress(e, info) {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    if (drag) cleanupDrag();
    drag = { info: info, id: e.pointerId, x0: e.clientX, y0: e.clientY, x: e.clientX, y: e.clientY, active: false,
             touch: e.pointerType === 'touch', src: e.currentTarget, timer: null, longReady: false, drop: null };
    if (info.kind === 'move') e.preventDefault();
    if (drag.touch && info.kind === 'new') {
      drag.timer = setTimeout(function () {
        if (drag && !drag.active) { drag.longReady = true; drag.src.classList.add('armed'); try { if (navigator.vibrate) navigator.vibrate(8); } catch (err) { /* no-op */ } }
      }, 230);
    }
    window.addEventListener('pointermove', onPointerMove, { passive: false });
    window.addEventListener('pointerup', onPointerUp);
    window.addEventListener('pointercancel', onPointerCancel);
  }
  function onPointerMove(e) {
    if (!drag || e.pointerId !== drag.id) return;
    drag.x = e.clientX; drag.y = e.clientY;
    var dist = Math.hypot(drag.x - drag.x0, drag.y - drag.y0);
    if (!drag.active) {
      if (drag.touch && drag.info.kind === 'new' && !drag.longReady) { if (dist > 10) cleanupDrag(); return; }
      if (dist < 5) return;
      activateDrag();
    }
    e.preventDefault();
    moveGhost();
    computeDrop();
  }
  function onPointerUp(e) {
    if (!drag || e.pointerId !== drag.id) return;
    if (drag.active) { finishDrop(); suppressClickUntil = Date.now() + 350; }
    else if (drag.longReady) { suppressClickUntil = Date.now() + 350; addLayer(drag.info.type, state.layers.length); }
    cleanupDrag();
  }
  function onPointerCancel(e) { if (drag && e.pointerId === drag.id) cleanupDrag(); }
  function activateDrag() {
    drag.active = true;
    document.body.classList.add('dragging');
    var type = drag.info.kind === 'new' ? drag.info.type : state.layers[indexOf(drag.info.uid)].type;
    ghost = el('div', { class: 'drag-ghost', style: '--h:' + HUES[type], 'aria-hidden': 'true' }, esc(C.LAYERS[type].name) + '<small></small>');
    document.body.appendChild(ghost);
    if (drag.info.kind === 'move') { var c = cardEls.get(drag.info.uid); if (c) c.classList.add('is-dragging'); }
    $('stack-panel').classList.add('drop-active');
    indicator = el('div', { class: 'drop-indicator', hidden: '' });
    $('stack-panel').appendChild(indicator);
    hideTip();
  }
  function moveGhost() {
    if (!ghost) return;
    ghost.style.transform = 'translate3d(' + (drag.x + 12) + 'px,' + (drag.y - 20) + 'px,0) rotate(-2deg) scale(1.04)';
  }
  function computeDrop() {
    var panel = $('stack-panel'), pr = panel.getBoundingClientRect();
    var pad = 28;
    var over = drag.x >= pr.left - pad && drag.x <= pr.right + pad && drag.y >= pr.top - pad && drag.y <= pr.bottom + pad;
    var others = state.layers.filter(function (l) { return !(drag.info.kind === 'move' && l.uid === drag.info.uid); });
    var idx = others.length;
    for (var i = 0; i < others.length; i++) {
      var r = cardEls.get(others[i].uid).getBoundingClientRect();
      if (drag.y < r.top + r.height / 2) { idx = i; break; }
    }
    drag.drop = over ? idx : null;
    ghost.classList.toggle('removing', !over && drag.info.kind === 'move');
    ghost.querySelector('small').textContent = !over && drag.info.kind === 'move' ? t('dropRemove') : (over ? '→ ' + (idx + 1) : '');
    if (!over || !others.length) { indicator.hidden = true; return; }
    indicator.hidden = false;
    var top;
    if (idx < others.length) top = cardEls.get(others[idx].uid).getBoundingClientRect().top - pr.top - 5;
    else { var lr = cardEls.get(others[others.length - 1].uid).getBoundingClientRect(); top = lr.bottom - pr.top + 2; }
    indicator.style.top = top + 'px';
    indicator.style.left = '16px'; indicator.style.right = '16px';
    // autoscroll near the viewport edges
    if (drag.y < 60) window.scrollBy(0, -12); else if (drag.y > window.innerHeight - 60) window.scrollBy(0, 12);
  }
  function finishDrop() {
    var d = drag.drop;
    if (drag.info.kind === 'new') { if (d != null) addLayer(drag.info.type, d); return; }
    var uid = drag.info.uid;
    if (d == null) { removeLayer(uid, false); return; }
    var from = indexOf(uid); if (from < 0) return;
    var L = state.layers[from];
    if (d === from) { update(); return; }
    commit(function () { state.layers.splice(from, 1); state.layers.splice(d, 0, L); }, t('moved', { layer: layerName(L), pos: d + 1, n: state.layers.length }));
  }
  function cleanupDrag() {
    if (!drag) return;
    clearTimeout(drag.timer);
    if (drag.src) drag.src.classList.remove('armed');
    if (drag.info.kind === 'move') { var c = cardEls.get(drag.info.uid); if (c) c.classList.remove('is-dragging'); }
    document.body.classList.remove('dragging');
    $('stack-panel').classList.remove('drop-active');
    if (ghost) { ghost.remove(); ghost = null; }
    if (indicator) { indicator.remove(); indicator = null; }
    window.removeEventListener('pointermove', onPointerMove);
    window.removeEventListener('pointerup', onPointerUp);
    window.removeEventListener('pointercancel', onPointerCancel);
    drag = null;
  }
  // stop page scrolling while a touch drag is armed or active
  document.addEventListener('touchmove', function (e) { if (drag && (drag.active || drag.longReady || drag.info.kind === 'move')) e.preventDefault(); }, { passive: false });
  document.addEventListener('contextmenu', function (e) { if (drag && drag.touch) e.preventDefault(); });

  // ------------------------------------------------------------------ init
  function init() {
    $('ver').textContent = C.VERSION;
    var th = storeGet('encap-theme'); if (th === 'dark' || th === 'light') document.documentElement.setAttribute('data-theme', th);
    var lg = storeGet('encap-lang'); if (lg === 'de' || lg === 'en') state.lang = lg;
    if (!readHash(location.hash)) {
      state.layers = [mkLayer('eth'), mkLayer('ipv4'), mkLayer('udp'), mkLayer('vxlan'), mkLayer('eth'), mkLayer('ipv4'), mkLayer('tcp')];
    }
    applyI18n();
    initTooltips();

    $('lang-en').addEventListener('click', function () { setLang('en'); });
    $('lang-de').addEventListener('click', function () { setLang('de'); });
    $('btn-theme').addEventListener('click', function () { setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'); });
    $('btn-share').addEventListener('click', function () {
      writeHash();
      copyText(location.href).then(function () { toast(t('shareCopied')); });
    });
    $('btn-clear').addEventListener('click', function () { commit(function () { state.layers = []; }, t('removed', { layer: '⨯ ' + t('clear') })); });
    $('mode-f').addEventListener('click', function () { state.mode = 'forward'; state.probe = null; update(); });
    $('mode-r').addEventListener('click', function () {
      if (state.mode !== 'reverse' && last && last.innerMTU > 0) state.target = Math.max(68, state.target || 1500);
      state.mode = 'reverse'; state.probe = null; update();
    });
    $('mtu').addEventListener('input', function () { var v = parseInt(this.value, 10); if (isFinite(v) && v > 0) { state.mtu = v; state.probe = null; state.preset = null; update(); } });
    $('mtu').addEventListener('change', function () { this.value = state.mtu; });
    $('target').addEventListener('input', function () { var v = parseInt(this.value, 10); if (isFinite(v) && v > 0) { state.target = v; state.probe = null; update(); } });
    $('target').addEventListener('change', function () { this.value = state.target; });
    $('probe').addEventListener('input', function () { var v = parseInt(this.value, 10); state.probe = v >= last.innerMTU ? null : v; update(); });
    $('probe-max').addEventListener('click', function () { state.probe = null; update(); });
    $('cfg-copy').addEventListener('click', function () {
      var b = this; copyText(cfgText).then(function () { b.textContent = t('copied'); setTimeout(function () { b.textContent = t('copy'); }, 1400); });
    });
    window.addEventListener('hashchange', function () {
      if (location.hash === lastHash) return;
      var first = rects();
      if (readHash(location.hash)) { lastHash = encode(); applyI18n(); update(); flip(first); }
    });
    var rz; window.addEventListener('resize', function () { clearTimeout(rz); rz = setTimeout(function () { if (last) { renderFrameBar(last); renderByteMap(last); } }, 120); });
    update();
    flip(new Map());
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
