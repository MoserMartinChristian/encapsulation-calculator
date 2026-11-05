#!/usr/bin/env node
/*
 * Browser test of the built index.html (file://, offline) with Playwright/Chromium.
 * Run: npm run test:e2e   (needs `playwright` resolvable, e.g. npm i -D playwright)
 * Checks: console errors, drag & drop (mouse + touch), keyboard, all presets,
 * MTU presets, reverse mode, URL sharing, theme, language, mobile layout.
 */
'use strict';
const path = require('path');
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require('playwright');

const FILE = 'file://' + path.resolve(__dirname, '..', 'index.html');
const SHOTS = process.env.SHOTS_DIR || path.resolve(__dirname, '..', 'docs');
const results = [];
async function step(name, fn) {
  try { await fn(); results.push(['PASS', name]); console.log('  ✓ ' + name); }
  catch (e) { results.push(['FAIL', name, e.message]); console.log('  ✗ ' + name + '\n    ' + e.message); }
}
const inner = (p) => p.$eval('#kpi-inner .num', (e) => e.textContent);
const types = (p) => p.$$eval('#stack .card strong', (els) => els.map((e) => e.textContent));
async function settle(p) { await p.waitForTimeout(650); }

async function dragTo(page, fromSel, toSel, where = 'top') {
  await page.locator(fromSel).first().scrollIntoViewIfNeeded();
  const a = await page.locator(fromSel).first().boundingBox();
  const b = await page.locator(toSel).first().boundingBox();
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.mouse.move(a.x + a.width / 2 + 10, a.y + a.height / 2 + 10, { steps: 3 });
  const ty = where === 'top' ? b.y + 4 : b.y + b.height - 4;
  await page.mouse.move(b.x + b.width / 2, ty, { steps: 12 });
  await page.mouse.up();
  await settle(page);
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {});
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('request', (r) => { if (!r.url().startsWith('file:') && !r.url().startsWith('data:')) errors.push('network request: ' + r.url()); });

  console.log('Desktop');
  await page.goto(FILE);
  await settle(page);

  await step('default stack loads (VXLAN over IPv4 = 1450)', async () => {
    assert.equal(await inner(page), '1450');
    assert.match(page.url(), /#m=1500&s=eth_ipv4_udp_vxlan_eth_ipv4_tcp/);
  });

  await step('all examples load with the expected inner MTU and no errors', async () => {
    const expected = { 'gre-ipsec': '1442', 'vxlan-evpn': '9166', 'wg-pppoe': '1432', 'mpls-l3vpn': '1492', geneve: '1542', sdwan: '1438' };
    for (const [id, v] of Object.entries(expected)) {
      await page.click(`[data-preset="${id}"]`);
      await settle(page);
      assert.equal(await inner(page), v, id);
      assert.equal(await page.$$eval('#warnings li.error', (x) => x.length), 0, id + ' has errors');
    }
  });

  await step('MTU presets 1500/1492/1600/9000/9216', async () => {
    await page.click('[data-preset="mpls-l3vpn"]'); await settle(page);
    for (const [m, v] of [[1500, '1492'], [1492, '1484'], [1600, '1592'], [9000, '8992'], [9216, '9208']]) {
      await page.click(`#mtu-presets button:text-is("${m}")`);
      await settle(page);
      assert.equal(await inner(page), v, 'mtu ' + m);
    }
  });

  await step('drag & drop with the mouse: add, reorder, remove', async () => {
    await page.click('#btn-clear'); await page.click('#mtu-presets button:text-is("1500")'); await settle(page);
    await dragTo(page, '.chip[data-type="eth"]', '#stack-empty');
    await dragTo(page, '.chip[data-type="ipv4"]', '#stack .card >> nth=0', 'bottom');
    await dragTo(page, '.chip[data-type="ipv4"]', '#stack .card >> nth=1', 'bottom');
    // insert GRE between the two IPv4 headers
    await dragTo(page, '.chip[data-type="gre"]', '#stack .card >> nth=2', 'top');
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE', 'IPv4']);
    assert.equal(await inner(page), '1476');
    assert.equal(await page.$eval('#kpi-mss4 .num', (e) => e.textContent), '1436');
    // reorder: drag GRE handle above the first IPv4 → invalid order shows an error
    await dragTo(page, '#stack .card >> nth=2 >> .handle', '#stack .card >> nth=1', 'top');
    assert.deepEqual(await types(page), ['Ethernet', 'GRE', 'IPv4', 'IPv4']);
    assert.ok(await page.$$eval('#warnings li.error', (x) => x.length) > 0, 'expected an order error');
    // drag it back
    await dragTo(page, '#stack .card >> nth=1 >> .handle', '#stack .card >> nth=2', 'bottom');
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE', 'IPv4']);
    // remove by dragging out of the stack
    await dragTo(page, '#stack .card >> nth=3 >> .handle', '#presets');
    await page.waitForTimeout(300);
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE']);
  });

  await step('keyboard: add with Enter, move with Alt+Arrow, delete', async () => {
    await page.focus('.chip[data-type="ipv6"]');
    await page.keyboard.press('Enter'); await settle(page);
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE', 'IPv6']);
    assert.equal(await page.$eval('#kpi-mss6 .num', (e) => e.textContent), '1416');
    await page.focus('#stack .card >> nth=3');
    await page.keyboard.press('Alt+ArrowUp'); await settle(page);
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'IPv6', 'GRE']);
    const focused = await page.evaluate(() => document.activeElement.querySelector('strong').textContent);
    assert.equal(focused, 'IPv6', 'focus follows the moved card');
    await page.keyboard.press('Alt+ArrowDown'); await settle(page);
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE', 'IPv6']);
    await page.keyboard.press('Delete'); await page.waitForTimeout(500);
    assert.deepEqual(await types(page), ['Ethernet', 'IPv4', 'GRE']);
    assert.ok((await page.textContent('#live')).length > 0, 'screen reader announcement');
  });

  await step('layer options: ESP cipher switch changes the result', async () => {
    await page.goto(FILE + '#m=1500&s=eth_ipv4_esp_ipv4'); await page.reload(); await settle(page);
    assert.equal(await inner(page), '1446');
    await page.click('#stack .card >> nth=2 >> .b-opt');
    await page.selectOption('#stack .card >> nth=2 >> select >> nth=1', 'aes-cbc'); await settle(page);
    assert.equal(await inner(page), '1438');
    await page.check('#stack .card >> nth=2 >> input[type=checkbox]'); await settle(page); // NAT-T
    assert.equal(await inner(page), '1422');
  });

  await step('reverse mode: inner 1500 over VXLAN needs 1550', async () => {
    await page.goto(FILE + '#m=1500&s=eth_ipv4_udp_vxlan_eth_ipv4'); await page.reload(); await settle(page);
    await page.click('#mode-r');
    await page.fill('#target', '1500'); await settle(page);
    assert.equal(await page.$eval('#kpi-req .num', (e) => e.textContent), '1550');
    assert.match(await page.textContent('#cfg-code'), /mtu 1550/);
    assert.match(page.url(), /mode=r&t=1500/);
  });

  await step('URL sharing restores the complete state in a fresh tab', async () => {
    await page.click('[data-preset="wg-pppoe"]'); await settle(page);
    await page.click('#mtu-presets button:text-is("1492")'); await settle(page);
    await page.click('#btn-share'); await page.waitForTimeout(200);
    const url = page.url();
    const p2 = await ctx.newPage();
    await p2.goto(url); await settle(p2);
    assert.deepEqual(await types(p2), ['Ethernet', 'PPPoE', 'IPv4', 'UDP', 'WireGuard', 'IPv4', 'TCP']);
    assert.equal(await inner(p2), '1424');
    assert.equal(await p2.inputValue('#mtu'), '1492');
    await p2.close();
    assert.match(await page.textContent('#toast'), /URL/);
  });

  await step('config tabs for all four vendors', async () => {
    for (const v of ['cisco', 'linux', 'mikrotik', 'juniper']) {
      await page.click('#tab-' + v);
      const code = await page.textContent('#cfg-code');
      assert.ok(code.length > 40, v);
      assert.match(code, /1384|1424/, v + ' contains computed values');
    }
  });

  await step('tooltip on a header field', async () => {
    await page.hover('#bytemap .fld >> nth=3');
    assert.equal(await page.isVisible('#tooltip'), true);
    assert.ok((await page.textContent('#tooltip')).includes('B ·'));
    await page.focus('#bytemap'); await page.keyboard.press('ArrowRight');
    assert.ok(await page.$eval('#bytemap', (e) => e.getAttribute('aria-activedescendant')));
  });

  await step('language switch EN → DE → EN', async () => {
    await page.click('#lang-de'); await settle(page);
    assert.equal(await page.getAttribute('html', 'lang'), 'de');
    assert.equal(await page.textContent('#h-stack'), 'Paket-Stack');
    assert.match(page.url(), /lang=de/);
    await page.click('#lang-en'); await settle(page);
    assert.equal(await page.textContent('#h-stack'), 'Packet stack');
  });

  await step('dark / light toggle', async () => {
    await page.click('[data-preset="gre-ipsec"]'); await settle(page);
    const bgDark = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    await page.screenshot({ path: path.join(SHOTS, 'screenshot-dark.png') });
    await page.click('#btn-theme'); await settle(page);
    assert.equal(await page.getAttribute('html', 'data-theme'), 'light');
    const bgLight = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert.notEqual(bgDark, bgLight);
    await page.screenshot({ path: path.join(SHOTS, 'screenshot-light.png') });
    await page.click('#btn-theme'); await settle(page);
    assert.equal(await page.getAttribute('html', 'data-theme'), 'dark');
  });

  await step('warnings: IPv6 below 1280 and VXLAN without Ethernet', async () => {
    await page.goto(FILE + '#m=1300&s=eth_ipv4_gre_ipv6'); await page.reload(); await settle(page);
    assert.ok(await page.$('#warnings li.error[data-code="IPV6_MIN"]'));
    await page.goto(FILE + '#m=1500&s=eth_ipv4_udp_vxlan_ipv4'); await page.reload(); await settle(page);
    assert.ok(await page.$('#warnings li.error[data-code="VXLAN_NEEDS_ETH"]'));
  });

  console.log('Mobile');
  for (const scheme of ['dark', 'light']) {
    const m = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: scheme });
    const mp = await m.newPage();
    mp.on('console', (x) => { if (x.type() === 'error') errors.push('[mobile] ' + x.text()); });
    mp.on('pageerror', (e) => errors.push('[mobile] ' + e.message));
    await mp.goto(FILE + '#m=1500&s=eth_ipv4_udp_vxlan_eth_ipv4_tcp'); await settle(mp);
    await step(`mobile ${scheme}: no horizontal scrolling, summary bar visible`, async () => {
      const ov = await mp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(ov <= 0, 'overflow ' + ov + 'px');
      assert.equal(await mp.isVisible('#summary-bar'), true);
      await mp.screenshot({ path: path.join(SHOTS, `screenshot-mobile-${scheme}.png`) });
    });
    if (scheme === 'dark') {
      await step('mobile: tap a palette layer appends it', async () => {
        await mp.click('#btn-clear'); await settle(mp);
        await mp.tap('.chip[data-type="eth"]'); await mp.tap('.chip[data-type="pppoe"]'); await mp.tap('.chip[data-type="ipv4"]');
        await settle(mp);
        assert.deepEqual(await types(mp), ['Ethernet', 'PPPoE', 'IPv4']);
        assert.equal(await inner(mp), '1492');
        assert.equal(await mp.$eval('#kpi-mss4 .num', (e) => e.textContent), '1452');
      });
      await step('mobile: touch drag (long-press chip, and handle reorder)', async () => {
        const cdp = await m.newCDPSession(mp);
        const touch = async (type, x, y) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchEnd' ? [] : [{ x, y }] });
        // reorder: move IPv4 (index 2) above PPPoE (index 1) via its handle
        await mp.evaluate(() => document.getElementById('stack').scrollIntoView({ block: 'center' }));
        let h = await mp.locator('#stack .card >> nth=2 >> .handle').boundingBox();
        let tgt = await mp.locator('#stack .card >> nth=1').boundingBox();
        await touch('touchStart', h.x + h.width / 2, h.y + h.height / 2);
        for (let i = 1; i <= 10; i++) await touch('touchMove', h.x + h.width / 2, h.y + h.height / 2 + (tgt.y + 4 - (h.y + h.height / 2)) * i / 10);
        await touch('touchEnd');
        await settle(mp);
        assert.deepEqual(await types(mp), ['Ethernet', 'IPv4', 'PPPoE']);
        // long-press a chip and drag it into the stack at the end
        await mp.evaluate(() => document.querySelector('#stack .card:last-child').scrollIntoView({ block: 'start' }));
        await mp.evaluate(() => window.scrollBy(0, -80));
        const chip = await mp.locator('.chip[data-type="mpls"]').boundingBox();
        const last = await mp.locator('#stack .card >> nth=2').boundingBox();
        await touch('touchStart', chip.x + chip.width / 2, chip.y + chip.height / 2);
        await mp.waitForTimeout(320);
        const end = { x: last.x + last.width / 2, y: last.y + last.height - 3 };
        for (let i = 1; i <= 12; i++) await touch('touchMove', chip.x + (end.x - chip.x) * i / 12, chip.y + (end.y - chip.y) * i / 12);
        await touch('touchEnd');
        await settle(mp);
        assert.deepEqual(await types(mp), ['Ethernet', 'IPv4', 'PPPoE', 'MPLS']);
      });
    }
    await m.close();
  }

  await step('no console errors and no network requests', async () => {
    assert.deepEqual(errors, []);
  });

  await browser.close();
  const failed = results.filter((r) => r[0] === 'FAIL');
  console.log(`\n${results.length - failed.length}/${results.length} browser checks passed`);
  fs.writeFileSync(path.join(SHOTS, 'e2e-results.txt'), results.map((r) => r.join(' – ')).join('\n') + '\n');
  process.exit(failed.length ? 1 : 0);
})();
