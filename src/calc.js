/*!
 * Encapsulation Calculator – calculation core
 * Pure functions only: no DOM access. Runs in the browser (window.EncapCalc)
 * and in Node.js (module.exports) so it can be tested in isolation.
 *
 * MODEL
 * -----
 * A stack is an ordered list of layers, outermost (first on the wire) first.
 *
 *   [outer L2 group]  Ethernet / 802.1Q / QinQ / MACsec at the start of the stack.
 *                     These bytes are added to the FRAME only. They do NOT
 *                     consume the underlay MTU (IEEE 802.3: MTU = max MAC client
 *                     data = 1500 for untagged and tagged frames).
 *   [MTU layers]      Everything after the outer L2 group (PPPoE, MPLS, IP,
 *                     UDP, tunnels, inner Ethernet ...) lives inside the
 *                     underlay MTU.
 *
 * "Underlay MTU" = the L3 MTU / maximum Ethernet payload of the physical link.
 * "Inner MTU"    = the largest packet that fits at the innermost IP layer
 *                  (the IP layer that carries only UDP/TCP or nothing).
 * "Overhead"     = underlay MTU - inner MTU (includes cipher block alignment loss).
 *
 * Every byte count below cites its source. See REFS.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.EncapCalc = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // References
  // ---------------------------------------------------------------------------
  var RFC = function (n) { return 'https://www.rfc-editor.org/rfc/rfc' + n; };
  var REFS = {
    'IEEE-802.3':   { t: 'IEEE 802.3 Ethernet – MAC header 14 B (DA 6, SA 6, EtherType 2), FCS 4 B, preamble+SFD 8 B, min. inter-packet gap 12 B, max. client data 1500 B', u: 'https://standards.ieee.org/ieee/802.3/10422/' },
    'IEEE-802.1Q':  { t: 'IEEE 802.1Q – VLAN tag 4 B (TPID 0x8100 + TCI); 802.1ad S-tag 4 B (TPID 0x88A8)', u: 'https://standards.ieee.org/ieee/802.1Q/10323/' },
    'IEEE-802.1AE': { t: 'IEEE 802.1AE MACsec – SecTAG 8 B, or 16 B with explicit SCI; ICV 16 B (GCM-AES cipher suites)', u: 'https://standards.ieee.org/ieee/802.1AE/7149/' },
    'CISCO-MACSEC': { t: 'Cisco xrdocs: MACsec on NCS-5500 – "16B SecTag and 16B ICV, so the data plane overhead is 32B"; SCI 8 B optional', u: 'http://xrdocs.io/ncs5500/tutorials/macsec-on-ncs-5500-technology-and-platform-overview' },
    RFC2516: { t: 'RFC 2516 – PPPoE: 6 B PPPoE header + 2 B PPP Protocol ID, max. payload 1492', u: RFC(2516) },
    RFC4638: { t: 'RFC 4638 – PPPoE MTU/MRU > 1492 (PPP-Max-Payload tag, "baby jumbo" 1508 underlay)', u: RFC(4638) },
    RFC3032: { t: 'RFC 3032 – MPLS label stack entry 4 B (Label 20 bit, TC 3, S 1, TTL 8)', u: RFC(3032) },
    RFC791:  { t: 'RFC 791 – IPv4 header 20 B + 0–40 B options (IHL in 32-bit words); every host must accept 576 B datagrams; min. MTU 68', u: RFC(791) },
    RFC8200: { t: 'RFC 8200 – IPv6 header 40 B; minimum link MTU 1280 B (Section 5)', u: RFC(8200) },
    RFC8754: { t: 'RFC 8754 – IPv6 Segment Routing Header: 8 B fixed + 16 B per SID', u: RFC(8754) },
    RFC8986: { t: 'RFC 8986 – SRv6 H.Encaps.Red: first SID not repeated in SRH; no SRH with a single SID', u: RFC(8986) },
    RFC768:  { t: 'RFC 768 – UDP header 8 B', u: RFC(768) },
    RFC9293: { t: 'RFC 9293 – TCP header 20 B without options; MSS excludes IP and TCP headers', u: RFC(9293) },
    RFC7323: { t: 'RFC 7323 – TCP Timestamps option 10 B (+2 B NOP padding = 12 B per segment)', u: RFC(7323) },
    RFC879:  { t: 'RFC 879 / RFC 6691 – MSS = MTU − 20 B IP − 20 B TCP (IPv6: MTU − 40 − 20)', u: RFC(6691) },
    RFC2784: { t: 'RFC 2784 – GRE base header 4 B; optional Checksum+Reserved1 4 B', u: RFC(2784) },
    RFC2890: { t: 'RFC 2890 – GRE Key 4 B and Sequence Number 4 B extensions', u: RFC(2890) },
    RFC7348: { t: 'RFC 7348 – VXLAN header 8 B over UDP (port 4789), carries an inner Ethernet frame (no inner FCS)', u: RFC(7348) },
    RFC8926: { t: 'RFC 8926 – Geneve: 8 B base header + 0–252 B options (multiple of 4) over UDP 6081', u: RFC(8926) },
    RFC9300: { t: 'RFC 9300 – LISP data-plane header 8 B over UDP 4341, carries IPv4/IPv6', u: RFC(9300) },
    RFC4303: { t: 'RFC 4303 – ESP: SPI 4 B + Sequence 4 B; trailer Pad Length 1 B + Next Header 1 B; padding aligns to cipher block size and to 4 B', u: RFC(4303) },
    RFC3602: { t: 'RFC 3602 – AES-CBC in ESP: IV 16 B, 16 B block size', u: RFC(3602) },
    RFC4106: { t: 'RFC 4106 – AES-GCM in ESP: IV 8 B, ICV 16 B (MAY 8 or 12), padding only to 4 B', u: RFC(4106) },
    RFC7634: { t: 'RFC 7634 – ChaCha20-Poly1305 in ESP: IV 8 B, ICV 16 B, padding only to 4 B', u: RFC(7634) },
    RFC4868: { t: 'RFC 4868 – HMAC-SHA-256-128 / -384-192 / -512-256: ICV 16 / 24 / 32 B', u: RFC(4868) },
    RFC2404: { t: 'RFC 2404 – HMAC-SHA-1-96: ICV 12 B', u: RFC(2404) },
    RFC8221: { t: 'RFC 8221 – ESP algorithm recommendations (ENCR_AES_GCM_16 MUST, 8/12 B ICV not recommended)', u: RFC(8221) },
    RFC3948: { t: 'RFC 3948 – ESP in UDP (NAT-T): 8 B UDP header, port 4500', u: RFC(3948) },
    'WG-PAPER': { t: 'WireGuard whitepaper §5.4.6 – transport data: type 1 B, reserved 3 B, receiver 4 B, counter 8 B, Poly1305 tag 16 B; plaintext padded to a multiple of 16 B', u: 'https://www.wireguard.com/papers/wireguard.pdf' },
    'WG-LINUX': { t: 'Linux drivers/net/wireguard (messages.h MESSAGE_PADDING_MULTIPLE = 16; send.c caps padding at the interface MTU)', u: 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireguard/send.c' },
    'WG-QUICK': { t: 'wg-quick: default MTU = underlay − 80 (IPv6 40 B + WireGuard 40 B incl. UDP) → 1420', u: 'https://lists.zx2c4.com/pipermail/wireguard/2023-November/008251.html' }
  };

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function clampInt(v, min, max, def) {
    var n = parseInt(v, 10);
    if (!isFinite(n)) return def;
    return Math.min(max, Math.max(min, n));
  }
  function round4(v) { return Math.floor(v / 4) * 4; }
  function f(name, bytes, d) { return { name: name, bytes: bytes, d: d || '' }; }

  var ESP_CIPHERS = {
    // iv: bytes on the wire, align: block size used for padding, aead: built-in ICV
    'aes-cbc':  { label: 'AES-CBC',           iv: 16, align: 16, aead: false, ref: 'RFC3602' },
    'aes-gcm':  { label: 'AES-GCM',           iv: 8,  align: 4,  aead: true,  ref: 'RFC4106' },
    'chacha20': { label: 'ChaCha20-Poly1305', iv: 8,  align: 4,  aead: true,  ref: 'RFC7634' }
  };
  var ESP_INTEG = {
    'sha1':   { label: 'HMAC-SHA-1-96',     icv: 12, ref: 'RFC2404' },
    'sha256': { label: 'HMAC-SHA-256-128',  icv: 16, ref: 'RFC4868' },
    'sha384': { label: 'HMAC-SHA-384-192',  icv: 24, ref: 'RFC4868' },
    'sha512': { label: 'HMAC-SHA-512-256',  icv: 32, ref: 'RFC4868' }
  };

  function espParams(o) {
    var c = ESP_CIPHERS[o.c] || ESP_CIPHERS['aes-gcm'];
    var icv;
    if (o.c === 'aes-cbc') icv = (ESP_INTEG[o.a] || ESP_INTEG.sha256).icv;
    else if (o.c === 'chacha20') icv = 16;
    else icv = o.i;
    var natt = o.n ? 8 : 0;
    return { iv: c.iv, align: c.align, icv: icv, natt: natt, fixed: natt + 8 + c.iv + icv };
  }

  // ---------------------------------------------------------------------------
  // Layer catalogue
  //   group: l2 | shim | l3 | l4 | tunnel | sec
  //   opts:  [{k, type:'int'|'bool'|'enum', def, min, max, step, values}]
  //   hdr(o, ctx)  -> header fields      trl(o, ctx) -> trailer fields
  //   cap(o, capIn, ctx) -> max payload (only for layers whose payload capacity
  //                         is not simply capIn - header - trailer)
  //   enc(o, payload, ctx) -> {pad} padding for a given payload size
  // ---------------------------------------------------------------------------
  var L2_TYPES = ['eth', 'dot1q', 'qinq', 'macsec'];
  var IP_TYPES = ['ipv4', 'ipv6'];
  var TUNNEL_TYPES = ['gre', 'vxlan', 'geneve', 'lisp', 'esp', 'wg', 'srv6', 'mpls', 'pppoe'];

  var LAYERS = {
    eth: {
      name: 'Ethernet', group: 'l2', refs: ['IEEE-802.3'], opts: [],
      hdr: function () {
        return [f('Destination MAC', 6, 'dst'), f('Source MAC', 6, 'src'), f('EtherType', 2, 'ethertype')];
      },
      // FCS only on the outermost (physical) Ethernet. Inner Ethernet inside
      // VXLAN/Geneve/GRE-TEB is carried without FCS (RFC 7348 §5).
      trl: function (o, ctx) { return ctx.outerL2 ? [f('FCS', 4, 'fcs')] : []; }
    },
    dot1q: {
      name: '802.1Q', group: 'l2', refs: ['IEEE-802.1Q'], opts: [],
      hdr: function () { return [f('TPID 0x8100', 2, 'tpid'), f('TCI (PCP/DEI/VID)', 2, 'tci')]; }
    },
    qinq: {
      name: 'QinQ', group: 'l2', refs: ['IEEE-802.1Q'], opts: [],
      hdr: function () {
        return [f('S-TPID 0x88A8', 2, 'stpid'), f('S-TCI (outer VID)', 2, 'tci'),
                f('C-TPID 0x8100', 2, 'tpid'), f('C-TCI (inner VID)', 2, 'tci')];
      }
    },
    macsec: {
      name: 'MACsec', group: 'sec', refs: ['IEEE-802.1AE', 'CISCO-MACSEC'],
      opts: [{ k: 'sci', type: 'bool', def: 1 }],
      hdr: function (o) {
        var r = [f('EtherType 0x88E5', 2, 'macsecet'), f('TCI/AN', 1, 'tcian'), f('Short Length', 1, 'sl'), f('Packet Number', 4, 'pn')];
        if (o.sci) r.push(f('SCI', 8, 'sci'));
        return r;
      },
      trl: function () { return [f('ICV', 16, 'micv')]; }
    },
    pppoe: {
      name: 'PPPoE', group: 'shim', refs: ['RFC2516', 'RFC4638'], opts: [],
      hdr: function () {
        return [f('Ver/Type', 1, 'pppver'), f('Code', 1, 'pppcode'), f('Session ID', 2, 'pppsess'),
                f('Length', 2, 'ppplen'), f('PPP Protocol', 2, 'pppproto')];
      }
    },
    mpls: {
      name: 'MPLS', group: 'shim', refs: ['RFC3032'],
      opts: [{ k: 'n', type: 'int', def: 2, min: 1, max: 12, step: 1 }],
      hdr: function (o) {
        var r = [];
        for (var i = 1; i <= o.n; i++) r.push(f('Label ' + i + (i === o.n ? ' (S=1)' : ''), 4, 'label'));
        return r;
      }
    },
    ipv4: {
      name: 'IPv4', group: 'l3', refs: ['RFC791'],
      opts: [{ k: 'o', type: 'int', def: 0, min: 0, max: 40, step: 4 }],
      hdr: function (o) {
        var r = [f('Version/IHL', 1, 'verihl'), f('DSCP/ECN', 1, 'dscp'), f('Total Length', 2, 'totlen'),
                 f('Identification', 2, 'ident'), f('Flags/Fragment Offset', 2, 'frag'), f('TTL', 1, 'ttl'),
                 f('Protocol', 1, 'proto'), f('Header Checksum', 2, 'csum'),
                 f('Source Address', 4, 'src4'), f('Destination Address', 4, 'dst4')];
        if (o.o) r.push(f('Options', o.o, 'ipopt'));
        return r;
      }
    },
    ipv6: {
      name: 'IPv6', group: 'l3', refs: ['RFC8200'], opts: [],
      hdr: function () {
        return [f('Version/TC/Flow Label', 4, 'v6first'), f('Payload Length', 2, 'plen'), f('Next Header', 1, 'nh'),
                f('Hop Limit', 1, 'hop'), f('Source Address', 16, 'src6'), f('Destination Address', 16, 'dst6')];
      }
    },
    srv6: {
      name: 'SRv6 SRH', group: 'tunnel', refs: ['RFC8754', 'RFC8986'],
      opts: [{ k: 'n', type: 'int', def: 2, min: 1, max: 16, step: 1 }, { k: 'r', type: 'bool', def: 0 }],
      hdr: function (o) {
        var sids = o.r ? o.n - 1 : o.n;
        if (sids <= 0) return [];
        var r = [f('Next Header', 1, 'nh'), f('Hdr Ext Len', 1, 'hel'), f('Routing Type 4', 1, 'rtype'),
                 f('Segments Left', 1, 'sl6'), f('Last Entry', 1, 'le'), f('Flags', 1, 'flags'), f('Tag', 2, 'tag')];
        for (var i = 0; i < sids; i++) r.push(f('Segment List[' + i + ']', 16, 'sid'));
        return r;
      }
    },
    udp: {
      name: 'UDP', group: 'l4', refs: ['RFC768'], opts: [],
      hdr: function () {
        return [f('Source Port', 2, 'sport'), f('Destination Port', 2, 'dport'), f('Length', 2, 'ulen'), f('Checksum', 2, 'ucsum')];
      }
    },
    tcp: {
      name: 'TCP', group: 'l4', refs: ['RFC9293', 'RFC7323'],
      opts: [{ k: 'ts', type: 'bool', def: 0 }],
      hdr: function (o) {
        var r = [f('Source Port', 2, 'sport'), f('Destination Port', 2, 'dport'), f('Sequence Number', 4, 'seq'),
                 f('Acknowledgment Number', 4, 'ack'), f('Data Offset/Flags', 2, 'tflags'), f('Window', 2, 'win'),
                 f('Checksum', 2, 'tcsum'), f('Urgent Pointer', 2, 'urg')];
        if (o.ts) r.push(f('NOP, NOP', 2, 'nop'), f('Timestamps (kind 8, len 10)', 10, 'tsopt'));
        return r;
      }
    },
    gre: {
      name: 'GRE', group: 'tunnel', refs: ['RFC2784', 'RFC2890'],
      opts: [{ k: 'c', type: 'bool', def: 0 }, { k: 'k', type: 'bool', def: 0 }, { k: 's', type: 'bool', def: 0 }],
      hdr: function (o) {
        var r = [f('Flags/Version', 2, 'greflags'), f('Protocol Type', 2, 'greproto')];
        if (o.c) r.push(f('Checksum', 2, 'grecsum'), f('Reserved1', 2, 'rsvd'));
        if (o.k) r.push(f('Key', 4, 'grekey'));
        if (o.s) r.push(f('Sequence Number', 4, 'greseq'));
        return r;
      }
    },
    vxlan: {
      name: 'VXLAN', group: 'tunnel', refs: ['RFC7348'], opts: [],
      hdr: function () { return [f('Flags (I)', 1, 'vxflags'), f('Reserved', 3, 'rsvd'), f('VNI', 3, 'vni'), f('Reserved', 1, 'rsvd')]; }
    },
    geneve: {
      name: 'Geneve', group: 'tunnel', refs: ['RFC8926'],
      opts: [{ k: 'o', type: 'int', def: 0, min: 0, max: 252, step: 4 }],
      hdr: function (o) {
        var r = [f('Ver/Opt Len', 1, 'gnver'), f('O/C flags', 1, 'gnflags'), f('Protocol Type', 2, 'greproto'),
                 f('VNI', 3, 'vni'), f('Reserved', 1, 'rsvd')];
        if (o.o) r.push(f('Options (TLVs)', o.o, 'gnopt'));
        return r;
      }
    },
    lisp: {
      name: 'LISP', group: 'tunnel', refs: ['RFC9300'], opts: [],
      hdr: function () { return [f('Flags N/L/E/V/I', 1, 'lispflags'), f('Nonce / Map-Version', 3, 'nonce'), f('Instance ID / LSBs', 4, 'iid')]; }
    },
    esp: {
      name: 'IPsec ESP', group: 'sec', refs: ['RFC4303', 'RFC3602', 'RFC4106', 'RFC7634', 'RFC4868', 'RFC2404', 'RFC3948', 'RFC8221'],
      opts: [
        { k: 'm', type: 'enum', def: 'tunnel', values: ['tunnel', 'transport'] },
        { k: 'n', type: 'bool', def: 0 },
        { k: 'c', type: 'enum', def: 'aes-gcm', values: ['aes-gcm', 'aes-cbc', 'chacha20'] },
        { k: 'b', type: 'enum', def: '256', values: ['128', '256'] },
        { k: 'i', type: 'enum', def: 16, values: [8, 12, 16] },
        { k: 'a', type: 'enum', def: 'sha256', values: ['sha1', 'sha256', 'sha384', 'sha512'] }
      ],
      hdr: function (o) {
        var p = espParams(o), r = [];
        if (p.natt) r.push(f('NAT-T UDP Src Port', 2, 'sport'), f('NAT-T UDP Dst Port 4500', 2, 'dport'),
                           f('NAT-T UDP Length', 2, 'ulen'), f('NAT-T UDP Checksum', 2, 'ucsum'));
        r.push(f('SPI', 4, 'spi'), f('Sequence Number', 4, 'espseq'), f('IV', p.iv, 'iv'));
        return r;
      },
      trl: function (o, ctx) {
        var p = espParams(o);
        var r = [];
        if (ctx.pad) r.push(f('Padding', ctx.pad, 'pad', true));
        r.push(f('Pad Length', 1, 'padlen', true), f('Next Header', 1, 'espnh', true), f('ICV', p.icv, 'icv'));
        return r;
      },
      cap: function (o, capIn) {
        var p = espParams(o);
        // encrypted part (payload + padding + 2) must be a multiple of align
        var avail = capIn - p.fixed;
        return Math.floor(avail / p.align) * p.align - 2;
      },
      pad: function (o, payload) {
        var p = espParams(o);
        return (p.align - ((payload + 2) % p.align)) % p.align;
      }
    },
    wg: {
      name: 'WireGuard', group: 'sec', refs: ['WG-PAPER', 'WG-LINUX', 'WG-QUICK'], opts: [],
      hdr: function () { return [f('Type = 4', 1, 'wgtype'), f('Reserved', 3, 'rsvd'), f('Receiver Index', 4, 'wgrecv'), f('Counter', 8, 'wgctr')]; },
      trl: function (o, ctx) {
        var r = [];
        if (ctx.pad) r.push(f('Padding (to 16 B)', ctx.pad, 'wgpad', true));
        r.push(f('Poly1305 Tag', 16, 'wgtag'));
        return r;
      },
      // Padding never exceeds the WireGuard interface MTU (send.c), so the max
      // payload is capIn - 32.
      pad: function (o, payload, ctx) {
        var padded = Math.ceil(payload / 16) * 16;
        if (padded > ctx.capOut) padded = ctx.capOut;
        return Math.max(0, padded - payload);
      }
    }
  };

  // Predecessors each layer may directly follow ('^' = start of stack).
  var FOLLOWS = {
    eth:    ['^', 'vxlan', 'geneve', 'gre', 'mpls'],
    dot1q:  ['eth', 'dot1q', 'qinq', 'macsec'],
    qinq:   ['eth', 'macsec'],
    macsec: ['eth'],
    pppoe:  ['eth', 'dot1q', 'qinq', 'macsec'],
    mpls:   ['^', 'eth', 'dot1q', 'qinq', 'macsec', 'pppoe', 'mpls', 'gre', 'udp'],
    ipv4:   ['^', 'eth', 'dot1q', 'qinq', 'macsec', 'pppoe', 'mpls', 'gre', 'esp', 'wg', 'lisp', 'geneve', 'ipv4', 'ipv6', 'srv6'],
    ipv6:   ['^', 'eth', 'dot1q', 'qinq', 'macsec', 'pppoe', 'mpls', 'gre', 'esp', 'wg', 'lisp', 'geneve', 'ipv4', 'ipv6', 'srv6'],
    srv6:   ['ipv6'],
    udp:    ['ipv4', 'ipv6', 'srv6', 'esp'],
    tcp:    ['ipv4', 'ipv6', 'srv6', 'esp'],
    gre:    ['ipv4', 'ipv6', 'srv6', 'esp'],
    vxlan:  ['udp'],
    geneve: ['udp'],
    lisp:   ['udp'],
    esp:    ['ipv4', 'ipv6', 'srv6'],
    wg:     ['udp']
  };

  // ---------------------------------------------------------------------------
  // Normalisation
  // ---------------------------------------------------------------------------
  function normalizeLayer(l) {
    var def = LAYERS[l && l.type];
    if (!def) return null;
    var o = {}, src = l.opts || {};
    def.opts.forEach(function (op) {
      var v = src[op.k];
      if (op.type === 'int') {
        var n = clampInt(v, op.min, op.max, op.def);
        if (op.step > 1) n = Math.floor(n / op.step) * op.step;
        o[op.k] = n;
      } else if (op.type === 'bool') {
        o[op.k] = (v === undefined || v === null || v === '') ? op.def : ((v === true || v === 1 || v === '1') ? 1 : 0);
      } else {
        var found = op.def;
        op.values.forEach(function (x) { if (String(x) === String(v)) found = x; });
        o[op.k] = found;
      }
    });
    return { type: l.type, opts: o };
  }

  function normalizeStack(layers) {
    return (layers || []).map(normalizeLayer).filter(Boolean);
  }

  // ---------------------------------------------------------------------------
  // Core analysis
  // ---------------------------------------------------------------------------
  function sumBytes(list) { return list.reduce(function (s, x) { return s + x.bytes; }, 0); }

  function l2GroupLength(layers) {
    var i = 0;
    while (i < layers.length && L2_TYPES.indexOf(layers[i].type) >= 0) i++;
    return i;
  }

  // Innermost IP layer that only carries UDP/TCP (or nothing). -1 if none.
  function anchorIndex(layers, start) {
    for (var i = layers.length - 1; i >= start; i--) {
      var t = layers[i].type;
      if (IP_TYPES.indexOf(t) >= 0) return i;
      if (t !== 'udp' && t !== 'tcp') return -1;
    }
    return -1;
  }

  function staticSizes(layer, ctx) {
    var def = LAYERS[layer.type];
    var h = def.hdr(layer.opts, ctx);
    var t = def.trl ? def.trl(layer.opts, ctx) : [];
    return { hdr: h, trl: t, h: sumBytes(h), t: sumBytes(t) };
  }

  /** Payload capacity of each MTU layer for a given underlay MTU. */
  function capacities(layers, l2len, mtu) {
    var caps = [];   // caps[i] = max size of the packet starting at layer i
    var cap = mtu;
    for (var i = l2len; i < layers.length; i++) {
      caps[i] = cap;
      var L = layers[i], def = LAYERS[L.type];
      if (def.cap) cap = def.cap(L.opts, cap);
      else {
        var s = staticSizes(L, { outerL2: false, pad: 0 });
        cap = cap - s.h - s.t;
      }
    }
    caps[layers.length] = cap; // payload capacity of the innermost layer
    return caps;
  }

  function innerInfo(layers, mtu) {
    var l2len = l2GroupLength(layers);
    var caps = capacities(layers, l2len, mtu);
    var a = anchorIndex(layers, l2len);
    var idx = a >= 0 ? a : layers.length;
    return { l2len: l2len, caps: caps, anchor: a, innerMTU: caps[idx], anchorPos: idx };
  }

  /**
   * analyze({mtu, layers, probe}) -> full result.
   * probe: size of the inner packet to draw (defaults to the inner MTU).
   */
  function analyze(state) {
    var layers = normalizeStack(state.layers);
    var mtu = clampInt(state.mtu, 0, 1000000, 1500);
    var info = innerInfo(layers, mtu);
    var l2len = info.l2len, caps = info.caps, a = info.anchor, pos = info.anchorPos;
    var innerMTU = info.innerMTU;
    var innerFamily = a >= 0 ? layers[a].type : null;

    var probe = state.probe == null || state.probe === '' ? innerMTU : clampInt(state.probe, 0, Math.max(0, innerMTU), innerMTU);
    if (innerMTU <= 0) probe = 0;

    // sizes[i] = actual size of the packet starting at layer i (for the probe)
    var sizes = [], detail = [];
    sizes[pos] = probe;
    // inward from the anchor (UDP/TCP after inner IP)
    for (var j = pos; j < layers.length; j++) {
      var sj = staticSizes(layers[j], { outerL2: false, pad: 0 });
      detail[j] = { hdr: sj.hdr, trl: sj.trl, h: sj.h, t: sj.t, pad: 0 };
      sizes[j + 1] = Math.max(0, sizes[j] - sj.h - sj.t);
    }
    // outward from the anchor
    for (var i = pos - 1; i >= l2len; i--) {
      var L = layers[i], def = LAYERS[L.type], payload = sizes[i + 1];
      var pad = def.pad ? def.pad(L.opts, payload, { capOut: caps[i + 1] }) : 0;
      var si = staticSizes(L, { outerL2: false, pad: pad });
      detail[i] = { hdr: si.hdr, trl: si.trl, h: si.h, t: si.t, pad: pad };
      sizes[i] = payload + si.h + si.t;
    }
    var packetSize = l2len < layers.length ? sizes[l2len] : probe;
    // outer L2 (frame only)
    var l2h = 0, l2t = 0;
    for (var k = 0; k < l2len; k++) {
      var sk = staticSizes(layers[k], { outerL2: true, pad: 0 });
      detail[k] = { hdr: sk.hdr, trl: sk.trl, h: sk.h, t: sk.t, pad: 0 };
      l2h += sk.h; l2t += sk.t;
    }
    var hasEth = l2len > 0 && layers[0].type === 'eth';
    var maxFrame = hasEth ? mtu + l2h + l2t : null;

    var mssV4 = innerMTU - 20 - 20, mssV6 = innerMTU - 40 - 20;
    if (innerFamily === 'ipv4') mssV4 -= layers[a].opts.o; // IPv4 options reduce MSS
    var tcpIdx = -1;
    layers.forEach(function (l, n) { if (l.type === 'tcp' && n > a && a >= 0) tcpIdx = n; });

    var res = {
      mtu: mtu,
      layers: layers,
      l2len: l2len,
      anchor: a,
      innerFamily: innerFamily,
      innerMTU: innerMTU,
      overhead: mtu - innerMTU,
      overheadPct: mtu > 0 ? (mtu - innerMTU) / mtu * 100 : 0,
      l2Overhead: l2h + l2t,
      mssV4: mssV4,
      mssV6: mssV6,
      mssInner: innerFamily === 'ipv6' ? mssV6 : mssV4,
      tsPayload: tcpIdx >= 0 && layers[tcpIdx].opts.ts ? (innerFamily === 'ipv6' ? mssV6 : mssV4) - 12 : null,
      frameSize: maxFrame,                         // L2 frame incl. FCS at full MTU
      wireSize: maxFrame != null ? maxFrame + 20 : null, // + preamble/SFD 8 + IPG 12
      probe: probe,
      packetSize: packetSize,
      probeFrame: hasEth ? packetSize + l2h + l2t : null,
      capacities: caps,
      sizes: sizes,
      detail: detail,
      warnings: []
    };
    res.warnings = validate(layers, res);
    res.layout = buildLayout(layers, res);
    return res;
  }

  // ---------------------------------------------------------------------------
  // Byte layout in wire order
  // ---------------------------------------------------------------------------
  function buildLayout(layers, res) {
    var heads = [], tails = [], payloadBytes = 0;
    var encFrom = []; // encFrom[i] = true when layer i lies inside an encrypted payload
    var inside = false;
    layers.forEach(function (l, i) {
      encFrom[i] = inside;
      if (l.type === 'esp' || l.type === 'wg' || l.type === 'macsec') inside = true;
    });
    layers.forEach(function (l, i) {
      var d = res.detail[i];
      if (!d) return;
      var outer = i < res.l2len;
      d.hdr.forEach(function (fl) {
        heads.push({ layer: i, type: l.type, name: fl.name, bytes: fl.bytes, key: fl.d, enc: encFrom[i], frameOnly: outer });
      });
      var t = d.trl.map(function (fl) {
        // ESP padding/pad length/next header and WG padding are encrypted
        return { layer: i, type: l.type, name: fl.name, bytes: fl.bytes, key: fl.d, enc: encFrom[i] || (fl.d === 'pad' || fl.d === 'padlen' || fl.d === 'espnh' || fl.d === 'wgpad'), frameOnly: outer, trailer: true };
      });
      tails.unshift.apply(tails, t);
    });
    var lastSize = res.sizes[layers.length];
    payloadBytes = lastSize != null ? lastSize : res.probe;
    var off = 0;
    var all = heads.concat([{ layer: -1, type: 'payload', name: 'Payload', bytes: Math.max(0, payloadBytes), key: 'payload', enc: inside, payload: true }]).concat(tails);
    all.forEach(function (x) { x.offset = off; off += x.bytes; });
    return { fields: all, total: off, encrypted: inside };
  }

  // ---------------------------------------------------------------------------
  // Validation – returns [{level:'error'|'warn'|'info', code, p:{...}}]
  // ---------------------------------------------------------------------------
  function validate(layers, res) {
    var w = [];
    function add(level, code, p) { w.push({ level: level, code: code, p: p || {} }); }
    if (!layers.length) { add('info', 'EMPTY'); return w; }

    if (res.mtu < 68) add('error', 'UNDERLAY_TOO_SMALL', { mtu: res.mtu });
    if (res.mtu > 65535) add('error', 'UNDERLAY_TOO_BIG', { mtu: res.mtu });

    layers.forEach(function (l, i) {
      var prev = i === 0 ? '^' : layers[i - 1].type;
      var allowed = FOLLOWS[l.type] || [];
      if (allowed.indexOf(prev) < 0) {
        if (prev === '^') add('error', 'BAD_START', { layer: LAYERS[l.type].name, i: i });
        else if (l.type === 'esp' && prev === 'udp') add('warn', 'ESP_USE_NATT', { i: i });
        else add('error', 'BAD_ORDER', { layer: LAYERS[l.type].name, prev: LAYERS[prev].name, i: i });
      }
      var next = layers[i + 1] ? layers[i + 1].type : null;
      if (l.type === 'vxlan' && next !== 'eth') add('error', 'VXLAN_NEEDS_ETH', { i: i });
      if (l.type === 'lisp' && next === 'eth') add('warn', 'LISP_ETH', { i: i });
      if (l.type === 'tcp' && next) add('error', 'AFTER_TCP', { i: i });
      if (l.type === 'esp') {
        var isIP = next === 'ipv4' || next === 'ipv6';
        if (l.opts.m === 'tunnel' && next && !isIP) add('error', 'ESP_TUNNEL_NEEDS_IP', { i: i });
        if (l.opts.m === 'transport' && isIP) add('warn', 'ESP_TRANSPORT_IP', { i: i });
        if (l.opts.c === 'aes-gcm' && l.opts.i !== 16) add('info', 'GCM_SHORT_ICV', { icv: l.opts.i, i: i });
        if (l.opts.c === 'aes-cbc' && l.opts.a === 'sha1') add('info', 'SHA1', { i: i });
      }
      if (['gre', 'vxlan', 'geneve', 'lisp', 'esp', 'wg'].indexOf(l.type) >= 0 && !next) add('info', 'TUNNEL_EMPTY', { layer: LAYERS[l.type].name, i: i });
      if (l.type === 'macsec' && i >= res.l2len) add('warn', 'MACSEC_INNER', { i: i });
      if (l.type === 'pppoe' && res.mtu > 1500) add('info', 'PPPOE_BABY_JUMBO', { i: i });
      if (l.type === 'srv6' && l.opts.r && l.opts.n === 1) add('info', 'SRV6_NO_SRH', { i: i });
      if (l.type === 'eth' && i > 0 && i < res.l2len) add('error', 'DUP_ETH', { i: i });
    });
    // de-duplicate identical BAD_ORDER entries
    var seen = {};
    w = w.filter(function (x) { var k = x.code + ':' + x.p.i; if (seen[k]) return false; seen[k] = 1; return true; });

    if (res.l2len > 0 && layers[0].type !== 'eth' && !w.some(function (x) { return x.code === 'BAD_START'; })) add('error', 'BAD_START', { layer: LAYERS[layers[0].type].name, i: 0 });

    if (res.innerMTU <= 0) add('error', 'NO_CAPACITY', { v: res.innerMTU });
    else if (res.innerFamily === 'ipv6' && res.innerMTU < 1280) add('error', 'IPV6_MIN', { v: res.innerMTU });
    else if (res.innerFamily === 'ipv4' && res.innerMTU < 68) add('error', 'IPV4_MIN68', { v: res.innerMTU });
    else if (res.innerFamily === 'ipv4' && res.innerMTU < 576) add('warn', 'IPV4_MIN', { v: res.innerMTU });
    if (res.innerMTU > 0 && res.innerFamily === 'ipv4' && res.innerMTU < 1280) add('info', 'NO_IPV6_INSIDE', { v: res.innerMTU });

    // Any IPv6 layer inside the MTU that is too small (e.g. outer IPv6 of an inner tunnel)
    for (var i = res.l2len; i < layers.length; i++) {
      if (layers[i].type === 'ipv6' && i !== res.anchor && res.capacities[i] < 1280) {
        add('error', 'IPV6_MIN_OUTER', { v: res.capacities[i], i: i });
        break;
      }
    }
    if (res.anchor < 0 && res.innerMTU > 0 && !w.some(function (x) { return x.code === 'TUNNEL_EMPTY' || x.code === 'VXLAN_NEEDS_ETH'; })) add('info', 'NO_INNER_IP');
    if (res.frameSize != null) {
      var std = 1518 + layers.slice(0, res.l2len).filter(function (l) { return l.type === 'dot1q'; }).length * 4;
      if (res.mtu <= 1500 && res.frameSize > Math.max(1522, std)) add('info', 'FRAME_OVERSIZE', { frame: res.frameSize });
      if (res.mtu > 1500) add('info', 'JUMBO_PATH', { mtu: res.mtu, frame: res.frameSize });
    }
    layers.slice(0, res.l2len).forEach(function (l) {
      if (l.type === 'macsec') add('info', 'MACSEC_FRAME', { bytes: l.opts.sci ? 32 : 24 });
    });
    return w;
  }

  // ---------------------------------------------------------------------------
  // Reverse mode: smallest underlay MTU that yields at least `target` inner MTU
  // ---------------------------------------------------------------------------
  function requiredUnderlay(layers, target) {
    layers = normalizeStack(layers);
    target = clampInt(target, 0, 1000000, 1500);
    var hi = 1000000;
    if (innerInfo(layers, hi).innerMTU < target) return null;
    var lo = 0;
    while (lo < hi) {
      var mid = Math.floor((lo + hi) / 2);
      if (innerInfo(layers, mid).innerMTU >= target) hi = mid; else lo = mid + 1;
    }
    return lo;
  }

  // ---------------------------------------------------------------------------
  // URL state  (#m=1500&s=eth_ipv4_esp.m-tunnel.c-aes-gcm_ipv4&mode=f&t=1500&lang=en)
  // ---------------------------------------------------------------------------
  function encodeLayer(l) {
    var def = LAYERS[l.type];
    var parts = [l.type];
    def.opts.forEach(function (op) {
      var v = l.opts[op.k];
      if (String(v) !== String(op.def)) parts.push(op.k + '-' + v);
    });
    return parts.join('.');
  }
  function decodeLayer(str) {
    var parts = String(str).split('.');
    var type = parts.shift();
    if (!LAYERS[type]) return null;
    var opts = {};
    parts.forEach(function (p) {
      var dash = p.indexOf('-');
      if (dash > 0) opts[p.slice(0, dash)] = p.slice(dash + 1);
    });
    return normalizeLayer({ type: type, opts: opts });
  }
  function encodeState(st) {
    var q = [];
    q.push('m=' + clampInt(st.mtu, 0, 1000000, 1500));
    q.push('s=' + normalizeStack(st.layers).map(encodeLayer).join('_'));
    if (st.mode === 'reverse') { q.push('mode=r'); q.push('t=' + clampInt(st.target, 0, 1000000, 1500)); }
    if (st.probe != null && st.probe !== '') q.push('p=' + clampInt(st.probe, 0, 1000000, 0));
    if (st.lang && st.lang !== 'en') q.push('lang=' + st.lang);
    return '#' + q.join('&');
  }
  function decodeState(hash) {
    var h = String(hash || '').replace(/^#/, '');
    if (!h) return null;
    var map = {};
    h.split('&').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) { try { map[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1)); } catch (e) { /* ignore */ } }
    });
    if (!('s' in map) && !('m' in map)) return null;
    var layers = (map.s || '').split('_').filter(Boolean).map(decodeLayer).filter(Boolean);
    return {
      mtu: clampInt(map.m, 0, 1000000, 1500),
      layers: layers,
      mode: map.mode === 'r' ? 'reverse' : 'forward',
      target: clampInt(map.t, 0, 1000000, 1500),
      probe: map.p != null && map.p !== '' ? clampInt(map.p, 0, 1000000, 0) : null,
      lang: map.lang === 'de' ? 'de' : (map.lang === 'en' ? 'en' : null)
    };
  }

  // ---------------------------------------------------------------------------
  // Presets
  // ---------------------------------------------------------------------------
  function L(type, opts) { return { type: type, opts: opts || {} }; }
  var PRESETS = [
    { id: 'gre-ipsec', name: 'GRE over IPsec', mtu: 1500,
      layers: [L('eth'), L('ipv4'), L('esp', { m: 'transport', c: 'aes-gcm', b: '256', i: 16 }), L('gre'), L('ipv4'), L('tcp')] },
    { id: 'vxlan-evpn', name: 'VXLAN EVPN', mtu: 9216,
      layers: [L('eth'), L('dot1q'), L('ipv4'), L('udp'), L('vxlan'), L('eth'), L('ipv4'), L('tcp')] },
    { id: 'wg-pppoe', name: 'WireGuard over PPPoE', mtu: 1500,
      layers: [L('eth'), L('pppoe'), L('ipv4'), L('udp'), L('wg'), L('ipv4'), L('tcp')] },
    { id: 'mpls-l3vpn', name: 'MPLS L3VPN', mtu: 1500,
      layers: [L('eth'), L('mpls', { n: 2 }), L('ipv4'), L('tcp')] },
    { id: 'geneve', name: 'Geneve', mtu: 1600,
      layers: [L('eth'), L('ipv4'), L('udp'), L('geneve', { o: 8 }), L('eth'), L('ipv4'), L('tcp')] },
    { id: 'sdwan', name: 'SD-WAN style', mtu: 1500,
      layers: [L('eth'), L('dot1q'), L('ipv4'), L('esp', { m: 'tunnel', n: 1, c: 'aes-gcm', b: '256', i: 16 }), L('ipv4'), L('tcp')] }
  ];

  return {
    VERSION: '1.0.0',
    REFS: REFS,
    LAYERS: LAYERS,
    FOLLOWS: FOLLOWS,
    ESP_CIPHERS: ESP_CIPHERS,
    ESP_INTEG: ESP_INTEG,
    PRESETS: PRESETS,
    L2_TYPES: L2_TYPES,
    TUNNEL_TYPES: TUNNEL_TYPES,
    espParams: espParams,
    normalizeLayer: normalizeLayer,
    normalizeStack: normalizeStack,
    analyze: analyze,
    requiredUnderlay: requiredUnderlay,
    encodeState: encodeState,
    decodeState: decodeState,
    layerHeaderBytes: function (l, outerL2) { var s = staticSizes(normalizeLayer(l), { outerL2: !!outerL2, pad: 0 }); return s.h + s.t; }
  };
});
