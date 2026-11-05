'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/calc.js');
const G = require('../src/config.js');

const L = (type, opts) => ({ type, opts: opts || {} });
const run = (layers, mtu = 1500, extra = {}) => C.analyze(Object.assign({ mtu, layers }, extra));
const codes = (r) => r.warnings.map((w) => w.code);

// ---------------------------------------------------------------- required
test('GRE without options over IPv4: MTU 1476, MSS 1436', () => {
  const r = run([L('eth'), L('ipv4'), L('gre'), L('ipv4')]);
  assert.equal(r.innerMTU, 1476);
  assert.equal(r.mssV4, 1436);
  assert.equal(r.overhead, 24);
});

test('VXLAN over IPv4: inner MTU 1450, MSS 1410', () => {
  const r = run([L('eth'), L('ipv4'), L('udp'), L('vxlan'), L('eth'), L('ipv4')]);
  assert.equal(r.innerMTU, 1450);
  assert.equal(r.mssV4, 1410);
  assert.equal(r.overhead, 50);
});

test('PPPoE: MTU 1492, MSS 1452', () => {
  const r = run([L('eth'), L('pppoe'), L('ipv4')]);
  assert.equal(r.innerMTU, 1492);
  assert.equal(r.mssV4, 1452);
});

test('MPLS with 2 labels: MTU 1492', () => {
  const r = run([L('eth'), L('mpls', { n: 2 }), L('ipv4')]);
  assert.equal(r.innerMTU, 1492);
});

test('WireGuard over IPv4: MTU 1440', () => {
  assert.equal(run([L('eth'), L('ipv4'), L('udp'), L('wg'), L('ipv4')]).innerMTU, 1440);
});

test('WireGuard over IPv6: MTU 1420', () => {
  assert.equal(run([L('eth'), L('ipv6'), L('udp'), L('wg'), L('ipv4')]).innerMTU, 1420);
});

test('ESP tunnel AES-256-GCM (8 IV, 16 ICV) over IPv4, no NAT-T: MTU 1446', () => {
  const r = run([L('eth'), L('ipv4'), L('esp', { m: 'tunnel', c: 'aes-gcm', b: '256', i: 16 }), L('ipv4')]);
  assert.equal(r.innerMTU, 1446);
});

test('ESP tunnel AES-256-CBC + HMAC-SHA-256-128 over IPv4, no NAT-T: MTU 1438', () => {
  const r = run([L('eth'), L('ipv4'), L('esp', { m: 'tunnel', c: 'aes-cbc', b: '256', a: 'sha256' }), L('ipv4')]);
  assert.equal(r.innerMTU, 1438);
});

test('GRE over IPv4 with inner IPv6: MSS 1416', () => {
  const r = run([L('eth'), L('ipv4'), L('gre'), L('ipv6')]);
  assert.equal(r.innerMTU, 1476);
  assert.equal(r.mssV6, 1416);
  assert.equal(r.mssInner, 1416);
});

// ---------------------------------------------------------------- more cases
test('L3 MTU vs frame: outer Ethernet is not part of the MTU', () => {
  const r = run([L('eth'), L('ipv4')]);
  assert.equal(r.innerMTU, 1500);
  assert.equal(r.overhead, 0);
  assert.equal(r.frameSize, 1518);
  assert.equal(r.wireSize, 1538);
  const q = run([L('eth'), L('dot1q'), L('ipv4')]);
  assert.equal(q.innerMTU, 1500);
  assert.equal(q.frameSize, 1522);
  assert.equal(run([L('eth'), L('qinq'), L('ipv4')]).frameSize, 1526);
});

test('MACsec adds 32 B (with SCI) / 24 B (without) to the frame, not the MTU', () => {
  const a = run([L('eth'), L('macsec', { sci: 1 }), L('ipv4')]);
  assert.equal(a.innerMTU, 1500);
  assert.equal(a.frameSize, 1518 + 32);
  const b = run([L('eth'), L('macsec', { sci: 0 }), L('ipv4')]);
  assert.equal(b.frameSize, 1518 + 24);
  assert.ok(codes(a).includes('MACSEC_FRAME'));
});

test('GRE options: checksum/key/sequence 4 B each', () => {
  assert.equal(run([L('eth'), L('ipv4'), L('gre', { k: 1 }), L('ipv4')]).innerMTU, 1472);
  assert.equal(run([L('eth'), L('ipv4'), L('gre', { c: 1, k: 1, s: 1 }), L('ipv4')]).innerMTU, 1464);
});

test('IPv4 options and TCP timestamps', () => {
  const r = run([L('eth'), L('ipv4', { o: 12 }), L('gre'), L('ipv4', { o: 8 }), L('tcp', { ts: 1 })]);
  assert.equal(r.innerMTU, 1464);
  assert.equal(r.mssV4, 1464 - 40 - 8);
  assert.equal(r.tsPayload, r.mssV4 - 12);
  // option length is forced to a multiple of 4 within 0..40
  assert.equal(C.normalizeLayer(L('ipv4', { o: 7 })).opts.o, 4);
  assert.equal(C.normalizeLayer(L('ipv4', { o: 99 })).opts.o, 40);
});

test('Geneve with options and VXLAN over IPv6', () => {
  assert.equal(run([L('eth'), L('ipv4'), L('udp'), L('geneve', { o: 8 }), L('eth'), L('ipv4')]).innerMTU, 1442);
  assert.equal(run([L('eth'), L('ipv6'), L('udp'), L('vxlan'), L('eth'), L('ipv4')]).innerMTU, 1430);
});

test('LISP over IPv4: 36 B overhead', () => {
  assert.equal(run([L('eth'), L('ipv4'), L('udp'), L('lisp'), L('ipv4')]).innerMTU, 1464);
});

test('SRv6: SRH 8 + 16·n, reduced encapsulation', () => {
  assert.equal(run([L('eth'), L('ipv6'), L('srv6', { n: 2 }), L('ipv4')]).innerMTU, 1500 - 40 - 8 - 32);
  assert.equal(run([L('eth'), L('ipv6'), L('srv6', { n: 2, r: 1 }), L('ipv4')]).innerMTU, 1500 - 40 - 8 - 16);
  assert.equal(run([L('eth'), L('ipv6'), L('srv6', { n: 1, r: 1 }), L('ipv4')]).innerMTU, 1460);
});

test('ESP: NAT-T, ChaCha20, transport mode and CBC alignment', () => {
  // NAT-T adds 8 B; GCM aligns to 4 B: 1500-20-8-8-8-16 = 1440 → 1438
  assert.equal(run([L('eth'), L('ipv4'), L('esp', { n: 1 }), L('ipv4')]).innerMTU, 1438);
  // ChaCha20-Poly1305: same sizes as GCM-16
  assert.equal(run([L('eth'), L('ipv4'), L('esp', { c: 'chacha20' }), L('ipv4')]).innerMTU, 1446);
  // GCM with 8 B ICV → 1454
  assert.equal(run([L('eth'), L('ipv4'), L('esp', { i: 8 }), L('ipv4')]).innerMTU, 1454);
  // CBC + SHA1-96: 1500-20-8-16-12 = 1444 → floor16 = 1440 → 1438
  assert.equal(run([L('eth'), L('ipv4'), L('esp', { c: 'aes-cbc', a: 'sha1' }), L('ipv4')]).innerMTU, 1438);
  // GRE over IPsec transport: ESP payload 1446 → GRE inner 1442
  const g = run([L('eth'), L('ipv4'), L('esp', { m: 'transport' }), L('gre'), L('ipv4')]);
  assert.equal(g.innerMTU, 1442);
});

test('ESP padding for a smaller probe packet (CBC block alignment)', () => {
  const r = run([L('eth'), L('ipv4'), L('esp', { c: 'aes-cbc', a: 'sha256' }), L('ipv4')], 1500, { probe: 1000 });
  // (1000 + 2) → next multiple of 16 = 1008 → pad 6
  assert.equal(r.detail[2].pad, 6);
  assert.equal(r.packetSize, 20 + 8 + 16 + 1000 + 6 + 2 + 16);
  // at maximum size the packet exactly fills the MTU
  const m = run([L('eth'), L('ipv4'), L('esp', { c: 'aes-cbc', a: 'sha256' }), L('ipv4')]);
  assert.equal(m.packetSize, 1500);
  assert.equal(m.detail[2].pad, 0);
});

test('WireGuard pads to 16 B but never beyond the interface MTU', () => {
  const st = [L('eth'), L('ipv4'), L('udp'), L('wg'), L('ipv4')];
  const r = run(st, 1500, { probe: 1001 });
  assert.equal(r.detail[3].pad, 7); // 1001 → 1008
  assert.equal(r.packetSize, 20 + 8 + 32 + 1008);
  const v6 = run([L('eth'), L('ipv6'), L('udp'), L('wg'), L('ipv4')]); // MTU 1420 is not a multiple of 16
  assert.equal(v6.detail[3].pad, 0);
  assert.equal(v6.packetSize, 1500);
});

test('Wire byte layout sums to the frame size', () => {
  const r = run([L('eth'), L('dot1q'), L('ipv4'), L('esp'), L('ipv4'), L('tcp')]);
  assert.equal(r.layout.total, r.frameSize);
  const fcs = r.layout.fields[r.layout.fields.length - 1];
  assert.equal(fcs.name, 'FCS');
});

test('Reverse mode: required underlay MTU', () => {
  assert.equal(C.requiredUnderlay([L('eth'), L('ipv4'), L('udp'), L('vxlan'), L('eth'), L('ipv4')], 1500), 1550);
  assert.equal(C.requiredUnderlay([L('eth'), L('pppoe'), L('ipv4')], 1500), 1508);
  // ESP CBC: alignment means 1562 is not enough
  const st = [L('eth'), L('ipv4'), L('esp', { c: 'aes-cbc' }), L('ipv4')];
  const m = C.requiredUnderlay(st, 1500);
  assert.ok(run(st, m).innerMTU >= 1500);
  assert.ok(run(st, m - 1).innerMTU < 1500);
  assert.equal(m, 1564);
});

test('Warnings: order, VXLAN without Ethernet, IPv6/IPv4 minimums', () => {
  assert.ok(codes(run([L('eth'), L('ipv4'), L('udp'), L('vxlan'), L('ipv4')])).includes('VXLAN_NEEDS_ETH'));
  assert.ok(codes(run([L('eth'), L('udp'), L('ipv4')])).includes('BAD_ORDER'));
  assert.ok(codes(run([L('dot1q'), L('ipv4')])).includes('BAD_START'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('gre'), L('ipv6')], 1300)).includes('IPV6_MIN'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('gre'), L('ipv4')], 590)).includes('IPV4_MIN'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('esp', { m: 'tunnel' }), L('gre'), L('ipv4')])).includes('ESP_TUNNEL_NEEDS_IP'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('tcp'), L('ipv4')])).includes('AFTER_TCP'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('udp'), L('esp'), L('ipv4')])).includes('ESP_USE_NATT'));
  assert.ok(codes(run([L('eth'), L('ipv4'), L('gre')])).includes('TUNNEL_EMPTY'));
  // a valid stack has no errors
  const ok = run([L('eth'), L('ipv4'), L('udp'), L('vxlan'), L('eth'), L('ipv4'), L('tcp')]);
  assert.equal(ok.warnings.filter((w) => w.level === 'error').length, 0);
});

test('All presets are valid and produce plausible results', () => {
  const expected = { 'gre-ipsec': 1442, 'vxlan-evpn': 9166, 'wg-pppoe': 1432, 'mpls-l3vpn': 1492, geneve: 1542, sdwan: 1438 };
  for (const p of C.PRESETS) {
    const r = run(p.layers, p.mtu);
    assert.equal(r.innerMTU, expected[p.id], p.id);
    assert.equal(r.warnings.filter((w) => w.level === 'error').length, 0, p.id + ' ' + JSON.stringify(r.warnings));
  }
});

test('URL state round trip', () => {
  const st = { mtu: 9000, layers: [L('eth'), L('ipv4'), L('esp', { m: 'transport', n: 1, c: 'aes-cbc', a: 'sha512' }), L('gre', { k: 1 }), L('ipv6'), L('tcp', { ts: 1 })], mode: 'reverse', target: 1500, probe: 800, lang: 'de' };
  const h = C.encodeState(st);
  assert.match(h, /^#m=9000&s=eth_ipv4_esp\./);
  const back = C.decodeState(h);
  assert.equal(back.mtu, 9000);
  assert.equal(back.mode, 'reverse');
  assert.equal(back.target, 1500);
  assert.equal(back.probe, 800);
  assert.equal(back.lang, 'de');
  assert.deepEqual(back.layers, C.normalizeStack(st.layers));
  // garbage is ignored
  assert.equal(C.decodeState('#foo=bar'), null);
  assert.deepEqual(C.decodeState('#m=1500&s=eth_bogus_ipv4').layers.map((l) => l.type), ['eth', 'ipv4']);
});

test('Every layer cites at least one known reference', () => {
  for (const [id, def] of Object.entries(C.LAYERS)) {
    assert.ok(def.refs.length > 0, id);
    for (const r of def.refs) assert.ok(C.REFS[r] && /^https?:\/\//.test(C.REFS[r].u), id + ' ' + r);
  }
});

// ---------------------------------------------------------------- config output
test('Config snippets contain the computed values', () => {
  const r = run([L('eth'), L('ipv4'), L('gre'), L('ipv4')]);
  const c = G.generate(r);
  assert.match(c.cisco, /interface Tunnel0\n ip mtu 1476\n ip tcp adjust-mss 1436/);
  assert.match(c.cisco, /ipv6 tcp adjust-mss 1416/);
  assert.match(c.linux, /ip link set dev gre1 mtu 1476/);
  assert.match(c.linux, /--tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1436/);
  assert.match(c.linux, /tcp option maxseg size set 1416/);
  assert.match(c.mikrotik, /\/interface gre set gre-tunnel1 mtu=1476/);
  assert.match(c.mikrotik, /tcp-mss=1437-65535 action=change-mss new-mss=1436/);
  assert.match(c.juniper, /set interfaces gr-0\/0\/0 unit 0 family inet mtu 1476/);
  assert.match(c.juniper, /set security flow tcp-mss gre-in mss 1436/);
  assert.doesNotMatch(c.linux, /eth0/); // underlay 1500 → no underlay line
});

test('Config: reverse mode shows underlay MTU, Junos media MTU includes L2 header', () => {
  const st = [L('eth'), L('dot1q'), L('ipv4'), L('udp'), L('vxlan'), L('eth'), L('ipv4')];
  const m = C.requiredUnderlay(st, 1500);
  const c = G.generate(run(st, m), { reverse: true });
  assert.match(c.linux, /ip link set dev eth0 mtu 1550/);
  assert.match(c.juniper, /set interfaces ge-0\/0\/0 mtu 1568/); // 1550 + 14 + 4
  assert.match(c.cisco, / mtu 1550/);
});

test('Config: Cisco adjust-mss range is respected for jumbo underlays', () => {
  const c = G.generate(run([L('eth'), L('ipv4'), L('gre'), L('ipv4')], 9000));
  assert.doesNotMatch(c.cisco, /ip tcp adjust-mss 8936/);
  assert.match(c.cisco, /outside that range/);
});

test('index.html is up to date with src/ (run npm run build)', () => {
  const fs = require('fs');
  const path = require('path');
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  for (const f of ['calc.js', 'config.js', 'i18n.js', 'app.js', 'styles.css']) {
    assert.ok(html.includes(fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8')), f + ' not inlined – rebuild');
  }
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+stylesheet/i, 'no external scripts or stylesheets');
});
