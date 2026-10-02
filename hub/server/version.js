'use strict';
// version.js — the ONE place that answers "which gre-hub build is this?".
//
// Resolution order (first hit wins):
//   1. build-info.json  — written by the release workflow into the tarball root
//   2. hub/VERSION      — canonical version, shipped in the tarball
//   3. ../VERSION       — source checkout (repo root)
//   4. package.json     — last-resort fallback
//
// Nothing here may ever hardcode a version: the whole point is that a stale
// deployed runtime is instantly visible in GET /api/meta and in the UI.

const fs = require('fs');
const path = require('path');

const HUB_ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(HUB_ROOT, '..');
const BUILD_INFO_FILE = path.join(HUB_ROOT, 'build-info.json');
const HUB_VERSION_FILE = path.join(HUB_ROOT, 'VERSION');
const REPO_VERSION_FILE = path.join(REPO_ROOT, 'VERSION');
const PACKAGE_FILE = path.join(HUB_ROOT, 'package.json');

function readText(file) {
  try { return fs.readFileSync(file, 'utf8').trim(); } catch { return ''; }
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function normalizeVersion(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  const cleaned = text.replace(/^v/i, '');
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(cleaned) ? cleaned : null;
}

function resolveMeta({ schemaVersion = null, gitFallback = null } = {}) {
  const buildInfo = readJson(BUILD_INFO_FILE);
  const sources = [];

  const fromBuild = buildInfo && normalizeVersion(buildInfo.version);
  const fromHubVersion = normalizeVersion(readText(HUB_VERSION_FILE));
  const fromRepoVersion = normalizeVersion(readText(REPO_VERSION_FILE));
  const pkg = readJson(PACKAGE_FILE);
  const fromPackage = pkg && normalizeVersion(pkg.version);

  let version = null;
  let source = 'unknown';
  if (fromBuild) { version = fromBuild; source = 'build-info.json'; }
  else if (fromHubVersion) { version = fromHubVersion; source = 'hub/VERSION'; }
  else if (fromRepoVersion) { version = fromRepoVersion; source = '../VERSION'; }
  else if (fromPackage) { version = fromPackage; source = 'package.json'; }

  for (const [name, value] of [
    ['build-info.json', fromBuild],
    ['hub/VERSION', fromHubVersion],
    ['../VERSION', fromRepoVersion],
    ['package.json', fromPackage],
  ]) sources.push({ name, version: value, agrees: value === null || value === version });

  const commit = (buildInfo && (buildInfo.commit || buildInfo.shortCommit)) || gitFallback || null;
  const builtAt = buildInfo && buildInfo.builtAt ? String(buildInfo.builtAt) : null;
  const tag = buildInfo && buildInfo.tag ? String(buildInfo.tag) : null;

  return {
    name: 'gre-hub',
    version,
    versionSource: source,
    commit: commit ? String(commit) : null,
    shortCommit: commit ? String(commit).slice(0, 7) : null,
    builtAt,
    tag,
    node: process.version,
    schemaVersion: schemaVersion === null || schemaVersion === undefined ? null : Number(schemaVersion),
    // Diagnostic only: shows every source we consulted and whether it agrees,
    // which is exactly what is needed to spot a half-updated deployment.
    sources,
    // True when at least one source actually disagrees with the resolved
    // version — a loud signal that a deployment is mixed.
    mixed: sources.some((item) => !item.agrees),
  };
}

module.exports = { resolveMeta, normalizeVersion, BUILD_INFO_FILE, HUB_VERSION_FILE, REPO_VERSION_FILE, HUB_ROOT };
