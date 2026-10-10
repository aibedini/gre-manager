'use strict';
// Render the real gre-hub in a real browser and prove the Connections page, the MTU
// columns and the health-check panel actually work. The Hub UI was previously only
// exercised with a DOM stub, which cannot catch CSS or event-wiring problems.
let chromium = null;
try {
  ({ chromium } = require('playwright'));
} catch {
  // Playwright is a heavy, optional dependency for a local browser check. Its absence is
  // reported as a skip, never as a pass.
  console.log('browser UI test: SKIPPED (playwright is not installed)');
  console.log('  install it with:  npm i -D playwright && npx playwright install chromium');
  if (process.env.UI_REQUIRE === '1') process.exit(1);
  process.exit(0);
}
const fs = require('fs');
const path = require('path');

const BASE = process.env.UI_BASE || 'http://127.0.0.1:4123';
const PASSWORD = process.env.UI_PASSWORD || 'uitest-pass-1';
const OUT = process.env.UI_OUT || path.join(require('os').tmpdir(), 'gre-hub-ui-shots');
fs.mkdirSync(OUT, { recursive: true });

let pass = 0; let fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) { pass += 1; console.log(`  ok    ${name}`); } else { fail += 1; console.log(`  FAIL  ${name} ${extra}`); }
};

(async () => {
  // A browser check needs a running Hub. Rather than fail a test run for an environment
  // that simply has none, probe first and skip with the exact command to run it.
  try {
    const probe = await fetch(BASE, { redirect: 'manual' });
    if (probe.status >= 500) throw new Error(`status ${probe.status}`);
  } catch (e) {
    console.log(`browser UI test: SKIPPED (no Hub listening at ${BASE}: ${e.message})`);
    console.log('  start one with:  bash boot-hub-for-ui.sh 4123   then re-run with UI_BASE set');
    if (process.env.UI_REQUIRE === '1') process.exit(1);
    process.exit(0);
  }

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1100 } });

  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];
  const httpErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', (e) => pageErrors.push(e.message));
  page.on('requestfailed', (r) => failedRequests.push(`${r.method()} ${r.url()} ${r.failure()?.errorText || ''}`));
  // Record WHICH request returned an error status, so a 401 is never waved away as noise.
  page.on('response', (r) => { if (r.status() >= 400) httpErrors.push(`${r.status()} ${r.request().method()} ${r.url()}`); });

  console.log('\n=== login ===');
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(OUT, '1-login.png') });
  const pwField = page.locator('input[type="password"]').first();
  if (await pwField.count()) {
    await pwField.fill(PASSWORD);
    await page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in")').first().click();
  }
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(OUT, '2-after-login.png') });
  const loggedIn = await page.locator('#view-main').isVisible().catch(() => false);
  check('the app renders after login', loggedIn, await page.title());

  console.log('\n=== the Connections page ===');
  const navBtn = page.locator('.nav button[data-page="connections"]');
  check('the Connections nav item exists', await navBtn.count() > 0);
  await navBtn.first().click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, '3-connections.png'), fullPage: true });

  const table = page.locator('table.conn-table');
  check('the connections table renders', await table.count() > 0);
  const headers = await page.locator('table.conn-table thead th').allTextContents();
  check('the table has headers', headers.length > 0, headers.join('|'));
  for (const want of ['Name', 'Iran Server', 'Foreign Server', 'Tunnel']) {
    check(`the table has a ${want} column`, headers.some((h) => h.includes(want)), headers.join('|'));
  }
  const bodyRows = await page.locator('table.conn-table tbody tr').count();
  check('the seeded connection is listed', bodyRows >= 1, `rows=${bodyRows}`);
  const rowText = bodyRows ? await page.locator('table.conn-table tbody tr').first().innerText() : '';
  check('the row shows the connection name', rowText.includes('de1'), rowText.slice(0, 120));
  check('the row shows both endpoints', rowText.includes('IR01') && rowText.includes('Hetz02'), rowText.slice(0, 160));

  const mtuHeaderText = headers.join('|').toUpperCase();
  check('MTU columns are present in the table', /MTU/.test(mtuHeaderText), headers.join('|'));

  console.log('\n=== the health-check action ===');
  const healthBtn = page.locator('button:has-text("Full Network Health Check")');
  check('the Full Network Health Check action exists', await healthBtn.count() > 0,
    (await page.locator('table.conn-table tbody tr').first().innerText()).slice(0, 200));
  if (await healthBtn.count()) {
    await healthBtn.first().click();
    await page.waitForTimeout(2000);
    await page.screenshot({ path: path.join(OUT, '4-health-panel.png'), fullPage: true });

    // Target the panel itself, not the server drawer that also happens to be open.
    const panel = page.locator('#connections-health');
    check('the health panel is visible', await panel.isVisible(), await panel.getAttribute('class'));
    const panelText = await panel.innerText().catch(() => '');
    check('the panel titles itself with the connection',
      /Full network health check/i.test(panelText) && panelText.includes('de1'), panelText.slice(0, 160));
    // The seeded hosts are fictional, so no diagnostic can have run: the panel must show
    // its empty state rather than stale or invented data.
    check('the panel shows an honest empty state until a check is run',
      /No diagnostic run loaded yet|NO CHECK YET/i.test(panelText), panelText.slice(0, 200));
    check('the panel does not invent a verdict before a run',
      !/BROKEN|HEALTHY|DEGRADED/.test(panelText), panelText.slice(0, 200));

    const links = await panel.locator('button').allTextContents().catch(() => []);
    const joined = links.join('|');
    for (const want of ['Run Quick Check', 'Run Full Check', 'Analyze MTU',
      'Export Diagnostic Report', 'Restore Previous State', 'Close']) {
      check(`the panel offers "${want}"`, joined.includes(want), joined.slice(0, 260));
    }

    // The two-column Check|Iran|Foreign table only exists once a run has been rendered,
    // so this drives a real run first. The seeded hosts are unreachable, which is fine:
    // what is being verified is that the panel renders the per-side result SHAPE and
    // reports a failure honestly instead of throwing.
    const quickBtn = page.locator('#btn-conn-health-quick');
    if (await quickBtn.count()) {
      await quickBtn.first().click();
      // Unreachable hosts fail on the ssh connect timeout (15s) per side, run in
      // parallel, so the honest wait is longer than that. Clicking again during the run
      // would be refused with 409 -- correct behaviour, but not what is under test here.
      let afterRun = '';
      for (let i = 0; i < 20; i += 1) {
        await page.waitForTimeout(2000);
        afterRun = await panel.innerText().catch(() => '');
        if (!/already running/i.test(afterRun) && afterRun.length > 40) break;
      }
      await page.screenshot({ path: path.join(OUT, '6-health-run.png'), fullPage: true });
      check('a run renders a result instead of throwing',
        await panel.isVisible() && afterRun.length > 0, afterRun.slice(0, 200));
      check('an unreachable pair is reported, not silently healthy',
        /unreachable|could not|failed|error|UNKNOWN|BROKEN/i.test(afterRun), afterRun.slice(0, 300));
      const headCells = await panel.locator('table thead th').allTextContents().catch(() => []);
      check('the health table renders a per-side header', headCells.length >= 3, headCells.join('|'));
      const bodyRows = await panel.locator('table tbody tr').count().catch(() => 0);
      check('the health table renders check rows', bodyRows > 0, `rows=${bodyRows}`);
    }

    // Clicking Close must actually hide it again, or the page is left unusable.
    const closeBtn = page.locator('#btn-conn-health-close');
    if (await closeBtn.count()) {
      await closeBtn.first().click();
      await page.waitForTimeout(500);
      check('closing the health panel hides it', !(await panel.isVisible()));
    }
    await page.screenshot({ path: path.join(OUT, '5-health-actions.png') });
  }

  console.log('\n=== HTTP statuses seen ===');
  const unexpected = httpErrors.filter((e) => !/^(401|409) /.test(e));
  for (const e of httpErrors) console.log('  ' + e);
  check('no unexpected HTTP error status', unexpected.length === 0, unexpected.slice(0, 3).join(' | '));

  console.log('\n=== console health ===');
  check('no uncaught page errors', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));
  // The browser logs every 4xx as a console error. Two are legitimate and expected:
  // `401 GET /api/me` is the app's own pre-login auth probe, and the 409 is the connection
  // lock refusing a second concurrent health check. Anything else is noise and must fail.
  const explanation = /status of (401|409)/;
  const realConsoleErrors = consoleErrors.filter((e) => !/favicon|net::ERR_/i.test(e) && !explanation.test(e));
  check('no console errors other than the expected 401 and 409', realConsoleErrors.length === 0,
    realConsoleErrors.slice(0, 3).join(' | '));
  const realFailed = failedRequests.filter((r) => !/favicon/i.test(r));
  check('no failed requests', realFailed.length === 0, realFailed.slice(0, 3).join(' | '));

  console.log('\n  screenshots in: ' + OUT);
  await browser.close();
  console.log(`\nUI checks: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('UI RUN FAILED:', e.message); process.exit(1); });
