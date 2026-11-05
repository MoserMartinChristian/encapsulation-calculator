/*!
 * Encapsulation Calculator – configuration snippet generator
 * Pure functions, no DOM. Only syntax that is documented by the vendor:
 *   Cisco IOS  : ip mtu / ip tcp adjust-mss (500–1460) / ipv6 tcp adjust-mss (40–1940)
 *                https://www.cisco.com/en/US/docs/ios-xml/ios/ipapp/command/iap-i2.html
 *   Linux      : ip link (man ip-link), iptables TCPMSS (man iptables-extensions),
 *                nftables "tcp option maxseg size set" (wiki.nftables.org, Mangling packet headers)
 *   MikroTik   : /ip|/ipv6 firewall mangle action=change-mss new-mss tcp-mss tcp-flags
 *                out-interface ipsec-policy (manual.mikrotik.com CLI reference 7.x)
 *   Juniper    : family inet|inet6 mtu, media MTU incl. L2 header (14 B, +4 per tag),
 *                set security flow tcp-mss all-tcp|gre-in|gre-out|ipsec-vpn mss (SRX)
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.EncapConfig = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var CONFIG_REFS = {
    cisco: [
      { t: 'Cisco IOS IP Application Services Command Reference – ip tcp adjust-mss / ipv6 tcp adjust-mss', u: 'https://www.cisco.com/en/US/docs/ios-xml/ios/ipapp/command/iap-i2.html' }
    ],
    linux: [
      { t: 'ip-link(8)', u: 'https://man7.org/linux/man-pages/man8/ip-link.8.html' },
      { t: 'iptables-extensions(8) – TCPMSS target', u: 'https://ipset.netfilter.org/iptables-extensions.man.html' },
      { t: 'nftables wiki – Mangling packet headers (TCP MSS)', u: 'https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers' },
      { t: 'wg-quick(8) – MTU', u: 'https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8' }
    ],
    mikrotik: [
      { t: 'RouterOS CLI reference – /ip firewall mangle', u: 'https://manual.mikrotik.com/docs/7.25/cli-reference/ip/firewall/mangle/' },
      { t: 'RouterOS CLI reference – /ipv6 firewall mangle', u: 'https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/firewall/mangle/' },
      { t: 'RouterOS Mangle – Change MSS example', u: 'https://help.mikrotik.com/docs/display/ROS/Mangle' }
    ],
    juniper: [
      { t: 'Junos – Media MTU (includes L2 header, excludes FCS)', u: 'https://juniper.net/documentation/us/en/software/junos/interfaces-fundamentals/topics/topic-map/media-mtu.html' },
      { t: 'Junos – security flow tcp-mss (all-tcp, gre-in, gre-out, ipsec-vpn)', u: 'https://juniper.net/documentation/en_US/junos12.1x46/topics/reference/configuration-statement/security-edit-tcp-mss.html' }
    ]
  };

  // The innermost "tunnel-ish" layer determines the interface the MTU goes on.
  function primaryKind(res) {
    var layers = res.layers;
    var end = res.anchor >= 0 ? res.anchor : layers.length;
    for (var i = end - 1; i >= res.l2len; i--) {
      var t = layers[i].type;
      if (t === 'gre' || t === 'esp' || t === 'wg' || t === 'vxlan' || t === 'geneve' || t === 'lisp' || t === 'pppoe' || t === 'mpls' || t === 'srv6') return t;
      if (t === 'eth') continue; // inner Ethernet of VXLAN/Geneve
    }
    return 'plain';
  }

  function vlanTags(res) {
    var n = 0;
    res.layers.slice(0, res.l2len).forEach(function (l) { if (l.type === 'dot1q') n += 1; if (l.type === 'qinq') n += 2; });
    return n;
  }

  function summary(res) {
    return res.layers.map(function (l) { return l.type; }).join(' / ');
  }

  // ---------------------------------------------------------------- Cisco IOS
  function cisco(res, ctx) {
    var k = primaryKind(res), o = [];
    var ifn = { gre: 'Tunnel0', esp: 'Tunnel0', pppoe: 'Dialer1' }[k];
    o.push('! Encapsulation Calculator – ' + summary(res));
    o.push('! Interface names are examples – adapt them to your device.');
    if (ctx.showUnderlay) {
      o.push('interface GigabitEthernet0/0');
      o.push(' mtu ' + res.mtu);
      o.push('!');
    }
    if (!ifn) {
      if (k === 'wg') o.push('! Cisco IOS has no WireGuard – clamp the MSS on the LAN-facing interface.');
      else if (k === 'vxlan' || k === 'geneve' || k === 'lisp' || k === 'mpls' || k === 'srv6') o.push('! ' + k.toUpperCase() + ': set the underlay MTU on the core links; clamp MSS on the inner L3 interface.');
      ifn = 'GigabitEthernet0/1';
      o.push('interface ' + ifn + '   ! inner / LAN-facing interface');
    } else {
      o.push('interface ' + ifn);
      o.push(' ip mtu ' + res.innerMTU);
    }
    if (res.mssV4 >= 500 && res.mssV4 <= 1460) o.push(' ip tcp adjust-mss ' + res.mssV4);
    else o.push(' ! ip tcp adjust-mss accepts 500–1460 – computed IPv4 MSS ' + res.mssV4 + ' is outside that range');
    if (res.innerMTU >= 1280) {
      if (ifn.indexOf('Tunnel') === 0 || ifn.indexOf('Dialer') === 0) o.push(' ipv6 mtu ' + res.innerMTU);
      if (res.mssV6 >= 40 && res.mssV6 <= 1940) o.push(' ipv6 tcp adjust-mss ' + res.mssV6);
      else o.push(' ! ipv6 tcp adjust-mss accepts 40–1940 – computed IPv6 MSS ' + res.mssV6 + ' is outside that range');
    } else {
      o.push(' ! inner MTU < 1280: IPv6 cannot be carried (RFC 8200)');
    }
    return o.join('\n');
  }

  // -------------------------------------------------------------------- Linux
  function linux(res, ctx) {
    var k = primaryKind(res), o = [];
    var dev = { gre: 'gre1', esp: 'vti0', wg: 'wg0', vxlan: 'vxlan0', geneve: 'geneve0', pppoe: 'ppp0' }[k] || 'tun0';
    o.push('# Encapsulation Calculator – ' + summary(res));
    o.push('# Device names are examples – adapt them.');
    if (ctx.showUnderlay) o.push('ip link set dev eth0 mtu ' + res.mtu + '        # underlay');
    if (k === 'esp') o.push('# policy-based IPsec has no tunnel device: skip the next line, keep the MSS rules');
    o.push('ip link set dev ' + dev + ' mtu ' + res.innerMTU);
    if (k === 'wg') o.push('# or in wg-quick ' + dev + '.conf, section [Interface]:  MTU = ' + res.innerMTU);
    o.push('');
    o.push('# MSS clamping – iptables / ip6tables');
    o.push('iptables  -t mangle -A FORWARD -o ' + dev + ' -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ' + res.mssV4);
    if (res.innerMTU >= 1280) o.push('ip6tables -t mangle -A FORWARD -o ' + dev + ' -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ' + res.mssV6);
    o.push('');
    o.push('# MSS clamping – nftables');
    o.push('nft add table inet mssfix');
    o.push("nft add chain inet mssfix forward '{ type filter hook forward priority mangle; }'");
    o.push('nft add rule inet mssfix forward oifname "' + dev + '" meta nfproto ipv4 tcp flags syn tcp option maxseg size set ' + res.mssV4);
    if (res.innerMTU >= 1280) o.push('nft add rule inet mssfix forward oifname "' + dev + '" meta nfproto ipv6 tcp flags syn tcp option maxseg size set ' + res.mssV6);
    return o.join('\n');
  }

  // ----------------------------------------------------------------- MikroTik
  function mikrotik(res, ctx) {
    var k = primaryKind(res), o = [];
    var map = {
      gre:   ['/interface gre set gre-tunnel1 mtu=' + res.innerMTU, 'gre-tunnel1'],
      wg:    ['/interface wireguard set wireguard1 mtu=' + res.innerMTU, 'wireguard1'],
      vxlan: ['/interface vxlan set vxlan1 mtu=' + res.innerMTU, 'vxlan1'],
      pppoe: ['/interface pppoe-client set pppoe-out1 max-mtu=' + res.innerMTU + ' max-mru=' + res.innerMTU, 'pppoe-out1']
    };
    o.push('# Encapsulation Calculator – ' + summary(res));
    o.push('# Interface names are examples – adapt them.');
    if (ctx.showUnderlay) o.push('/interface ethernet set ether1 mtu=' + res.mtu + '   # underlay (check l2mtu)');
    var match;
    if (map[k]) { o.push(map[k][0]); match = 'out-interface=' + map[k][1]; }
    else if (k === 'esp') { o.push('# IPsec (policy-based): no tunnel interface – match on the IPsec policy'); match = 'ipsec-policy=out,ipsec'; }
    else { o.push('# no RouterOS interface MTU line for this stack – MSS clamp only'); match = 'out-interface=ether1'; }
    o.push('/ip firewall mangle add chain=forward ' + match + ' protocol=tcp tcp-flags=syn tcp-mss=' + (res.mssV4 + 1) + '-65535 action=change-mss new-mss=' + res.mssV4 + ' passthrough=yes');
    if (res.innerMTU >= 1280) o.push('/ipv6 firewall mangle add chain=forward ' + match + ' protocol=tcp tcp-flags=syn tcp-mss=' + (res.mssV6 + 1) + '-65535 action=change-mss new-mss=' + res.mssV6 + ' passthrough=yes');
    return o.join('\n');
  }

  // ------------------------------------------------------------------ Juniper
  function juniper(res, ctx) {
    var k = primaryKind(res), o = [];
    var ifl = { gre: 'gr-0/0/0', esp: 'st0', pppoe: 'pp0' }[k];
    o.push('# Encapsulation Calculator – ' + summary(res));
    o.push('# Interface names are examples – adapt them.');
    if (ctx.showUnderlay) {
      var tags = vlanTags(res);
      o.push('# media MTU includes the 14-byte Ethernet header' + (tags ? ' + ' + (4 * tags) + ' bytes VLAN tags' : '') + ' (no FCS)');
      o.push('set interfaces ge-0/0/0 mtu ' + (res.mtu + 14 + 4 * tags));
    }
    if (ifl) {
      o.push('set interfaces ' + ifl + ' unit 0 family inet mtu ' + res.innerMTU);
      if (res.innerMTU >= 1280) o.push('set interfaces ' + ifl + ' unit 0 family inet6 mtu ' + res.innerMTU);
    } else if (k === 'wg') {
      o.push('# Junos has no WireGuard – MSS clamp only');
    } else {
      o.push('# ' + (k === 'plain' ? 'plain IP' : k.toUpperCase()) + ': no tunnel interface MTU – MSS clamp only');
    }
    var mss = res.innerFamily === 'ipv6' ? res.mssV6 : res.mssV4;
    o.push('# SRX flow mode: TCP MSS of SYN packets');
    if (k === 'gre') {
      o.push('set security flow tcp-mss gre-in mss ' + mss);
      o.push('set security flow tcp-mss gre-out mss ' + mss);
    } else if (k === 'esp') {
      o.push('set security flow tcp-mss ipsec-vpn mss ' + mss);
    } else {
      o.push('set security flow tcp-mss all-tcp mss ' + mss);
    }
    return o.join('\n');
  }

  function generate(res, opts) {
    opts = opts || {};
    var ctx = { showUnderlay: opts.reverse || res.mtu !== 1500 };
    if (res.innerMTU <= 0) {
      var msg = '# No valid result – fix the stack first.';
      return { cisco: msg.replace('#', '!'), linux: msg, mikrotik: msg, juniper: msg };
    }
    return { cisco: cisco(res, ctx), linux: linux(res, ctx), mikrotik: mikrotik(res, ctx), juniper: juniper(res, ctx) };
  }

  return { generate: generate, primaryKind: primaryKind, CONFIG_REFS: CONFIG_REFS };
});
