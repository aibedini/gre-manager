'use strict';
// version-test.js — the single source of version truth.
//
// 1. all five in-repo version sources must agree (same rule CI enforces)
// 2. server/version.js must resolve in the documented precedence order and
//    flag a mixed deployment
// 3. GET /api/meta must report the running build
//
// Run with: node scripts/version-test.js

const { assert, check, checkAsync, report } = require('./_harness');
const fs = require('fs');
const os = require('os');
const path = require('path');

const HUB_ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(HUB_ROOT, '..');

function readTrim(file) {
  return fs.readFileSync(file, 'utf8').trim();
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// Build a throwaway tree that mirrors the real layout, so server/version.js
// resolves against fixtures instead of the working copy.
function fixtureTree({ buildInfo = null, hubVersion = '9.9.9', repoVersion = '9.9.9', packageVersion = '9.9.9' } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-version-'));
  const hub = path.join(root, 'hub');
  fs.mkdirSync(path.join(hub, 'server'), { recursive: true });
  fs.copyFileSync(path.join(HUB_ROOT, 'server', 'version.js'), path.join(hub, 'server', 'version.js'));
  if (buildInfo) fs.writeFileSync(path.join(hub, 'build-info.json'), JSON.stringify(buildInfo));
  if (hubVersion !== null) fs.writeFileSync(path.join(hub, 'VERSION'), `${hubVersion}\n`);
  if (repoVersion !== null) fs.writeFileSync(path.join(root, 'VERSION'), `${repoVersion}\n`);
  fs.writeFileSync(path.join(hub, 'package.json'), JSON.stringify({ name: 'gre-hub', version: packageVersion }, null, 2));
  return { root, hub };
}

function loadFixtureVersion() {
  const { root, hub } = fixtureTree.apply(null, arguments);
  // eslint-disable-next-line global-require, import/no-dynamic-require
  const mod = require(path.join(hub, 'server', 'version.js'));
  return { mod, root };
}

async function main() {
  console.log('in-repo version sources:');

  const versionFile = readTrim(path.join(REPO_ROOT, 'VERSION'));
  const scriptVersion = (fs.readFileSync(path.join(REPO_ROOT, 'gre-manager.sh'), 'utf8')
    .match(/^VERSION="([^"]+)"/m) || [])[1];
  const packageVersion = readJson(path.join(HUB_ROOT, 'package.json')).version;
  const lock = readJson(path.join(HUB_ROOT, 'package-lock.json'));
  const hubVersion = readTrim(path.join(HUB_ROOT, 'VERSION'));
  const changelog = fs.readFileSync(path.join(REPO_ROOT, 'CHANGELOG.md'), 'utf8');

  check('VERSION, gre-manager.sh, hub/VERSION, package.json and package-lock agree', () => {
    const sources = {
      'VERSION': versionFile,
      'gre-manager.sh': scriptVersion,
      'hub/VERSION': hubVersion,
      'hub/package.json': packageVersion,
      'hub/package-lock.json': lock.version,
      'hub/package-lock.json packages[""]': lock.packages[''].version,
    };
    const distinct = [...new Set(Object.values(sources))];
    assert.equal(distinct.length, 1, `version sources disagree: ${JSON.stringify(sources)}`);
    assert.match(versionFile, /^\d+\.\d+\.\d+$/, `VERSION is not semver: ${versionFile}`);
  });

  check('the version has a CHANGELOG section', () => {
    assert(changelog.includes(`## [${versionFile}]`), `CHANGELOG has no "## [${versionFile}]" section`);
  });

  check('hub/package-lock.json was not hand-edited into a shape npm rejects', () => {
    assert.equal(lock.lockfileVersion, 3);
    assert(lock.packages[''], 'packages[""] block is required by lockfileVersion 3');
  });

  check('the hub ships the install policy that lets native modules build', () => {
    // Regression guard: without this file npm 11+ silently skips dependency
    // install scripts and better-sqlite3 ends up with no compiled binding, so a
    // freshly deployed hub cannot open its database.
    const npmrcPath = path.join(HUB_ROOT, '.npmrc');
    assert(fs.existsSync(npmrcPath), 'hub/.npmrc is missing from the package');
    const body = fs.readFileSync(npmrcPath, 'utf8');
    assert(/^\s*allow-scripts\s*=\s*true\s*$/m.test(body),
      'hub/.npmrc must enable allow-scripts so better-sqlite3 compiles');
    // The released tarball is produced from the working tree, so a top-level
    // .gitignore entry would silently drop it from the artifact.
    const rootIgnore = fs.readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8');
    assert(!/^\s*\.npmrc\s*$/m.test(rootIgnore), '.gitignore must not exclude .npmrc');
    const hubIgnore = fs.readFileSync(path.join(HUB_ROOT, '.gitignore'), 'utf8');
    assert(!/^\s*\.npmrc\s*$/m.test(hubIgnore), 'hub/.gitignore must not exclude .npmrc');
  });

  console.log('\nresolution order:');

  check('build-info.json wins over every other source', () => {
    const { mod } = loadFixtureVersion({
      buildInfo: { version: '7.7.7', commit: 'abcdef1234567890', shortCommit: 'abcdef1', builtAt: '2026-01-01T00:00:00Z', tag: 'v7.7.7' },
      hubVersion: '9.9.9', repoVersion: '9.9.9', packageVersion: '9.9.9',
    });
    const meta = mod.resolveMeta();
    assert.equal(meta.version, '7.7.7');
    assert.equal(meta.versionSource, 'build-info.json');
    assert.equal(meta.shortCommit, 'abcdef1');
    assert.equal(meta.builtAt, '2026-01-01T00:00:00Z');
    assert.equal(meta.tag, 'v7.7.7');
    assert.equal(meta.mixed, true, 'disagreeing sources must be flagged');
  });

  check('hub/VERSION is used when build-info.json is absent', () => {
    const { mod } = loadFixtureVersion({ hubVersion: '2.12.0', repoVersion: '2.12.0', packageVersion: '2.12.0' });
    const meta = mod.resolveMeta();
    assert.equal(meta.version, '2.12.0');
    assert.equal(meta.versionSource, 'hub/VERSION');
    assert.equal(meta.mixed, false);
  });

  check('../VERSION is used for a source checkout with no hub/VERSION', () => {
    const { mod } = loadFixtureVersion({ hubVersion: null, repoVersion: '5.5.5', packageVersion: '5.5.5' });
    const meta = mod.resolveMeta();
    assert.equal(meta.version, '5.5.5');
    assert.equal(meta.versionSource, '../VERSION');
  });

  check('package.json is the last-resort fallback', () => {
    const { mod } = loadFixtureVersion({ hubVersion: null, repoVersion: null, packageVersion: '6.6.6' });
    const meta = mod.resolveMeta();
    assert.equal(meta.version, '6.6.6');
    assert.equal(meta.versionSource, 'package.json');
  });

  check('a malformed version is rejected rather than reported', () => {
    const { mod } = loadFixtureVersion({ buildInfo: { version: 'not-a-version' }, hubVersion: 'not-a-version', repoVersion: null, packageVersion: '4.4.4' });
    const meta = mod.resolveMeta();
    assert.equal(meta.version, '4.4.4', 'the first *valid* source must win');
    assert.equal(meta.versionSource, 'package.json');
  });

  check('a leading v is normalized away', () => {
    const { mod } = loadFixtureVersion({ buildInfo: { version: 'v3.8.5' }, hubVersion: '3.8.5' });
    assert.equal(mod.resolveMeta().version, '3.8.5');
  });

  check('the source checkout resolves to the repo version and reports the schema', () => {
    const versionModule = require('../server/version');
    const meta = versionModule.resolveMeta({ schemaVersion: 2 });
    assert.equal(meta.version, versionFile, 'source checkout must report the repo VERSION');
    assert.equal(meta.schemaVersion, 2);
    assert.equal(meta.name, 'gre-hub');
    assert(meta.node.startsWith('v'));
    assert.equal(meta.mixed, false, `unexpected mixed sources: ${JSON.stringify(meta.sources)}`);
  });

  console.log('\nGET /api/meta:');

  await checkAsync('the live server reports the exact running build', async () => {
    // Boot the real hub the same way the events suite does.
    const { spawn } = require('child_process');
    const net = require('net');
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const pickPort = async () => {
      for (let i = 0; i < 40; i++) {
        const candidate = 46000 + Math.floor(Math.random() * 15000);
        // eslint-disable-next-line no-await-in-loop
        const free = await new Promise((resolve) => {
          const server = net.createServer();
          server.once('error', () => resolve(false));
          server.once('listening', () => server.close(() => resolve(true)));
          server.listen(candidate, '127.0.0.1');
        });
        if (free) return candidate;
      }
      throw new Error('no free port');
    };
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-meta-'));
    const port = await pickPort();
    const child = spawn(process.execPath, [path.join(HUB_ROOT, 'server', 'index.js')], {
      env: { ...process.env, PORT: String(port), HUB_HOST: '127.0.0.1', HUB_DATA_DIR: dataDir },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    try {
      let buf = '';
      child.stdout.on('data', (d) => { buf += d; });
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline && !buf.includes('gre-hub listening')) {
        if (child.exitCode !== null) throw new Error(`hub exited early (${child.exitCode})\n${buf}`);
        // eslint-disable-next-line no-await-in-loop
        await sleep(100);
      }
      assert(buf.includes('gre-hub listening'), `hub did not start\n${buf}`);
      assert(/gre-hub build: v\d/.test(buf), `startup did not print the build line\n${buf}`);

      const res = await fetch(`http://127.0.0.1:${port}/api/meta`);
      assert.equal(res.status, 200, `expected 200, got ${res.status}`);
      const meta = await res.json();
      assert.equal(meta.name, 'gre-hub');
      assert.equal(meta.version, versionFile, `meta version ${meta.version} != repo VERSION ${versionFile}`);
      assert.equal(meta.schemaVersion, 2, 'schema version must be reported');
      assert(meta.node.startsWith('v'));
      assert(Array.isArray(meta.sources) && meta.sources.length === 4, 'all sources must be reported');
      assert(!JSON.stringify(meta).match(/secret|token|password_enc/i), 'meta must not leak secrets');
      assert(typeof meta.uptimeSeconds === 'number');

      // The endpoint must be reachable without a session: it is how an
      // operator checks a deployment before logging in.
      const anon = await fetch(`http://127.0.0.1:${port}/api/meta`);
      assert.equal(anon.status, 200, 'GET /api/meta must not require auth');
    } finally {
      child.kill('SIGTERM');
      await sleep(300);
      if (child.exitCode === null) child.kill('SIGKILL');
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  });

  report('version/meta tests');
}

main().catch((err) => { console.error(err); process.exit(1); });
