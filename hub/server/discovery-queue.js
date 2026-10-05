'use strict';
// discovery-queue.js — bounded concurrency with per-target coalescing.
//
// Why this exists: auto refresh used to fire a full SSH discovery at every server
// simultaneously. With 20-30 servers that is 20-30 concurrent SSH sessions every
// few seconds: a thundering herd that makes transient failures far more likely,
// which is exactly the condition that used to wipe topology.
//
// Two guarantees:
//   1. never more than `concurrency` tasks in flight,
//   2. at most ONE in-flight task per key; a second request for the same key
//      joins the first instead of opening another SSH session.

const DEFAULT_CONCURRENCY = 4;

function readConcurrency(env) {
  const raw = Number((env || process.env || {}).HUB_DISCOVERY_CONCURRENCY);
  if (!Number.isFinite(raw) || raw < 1) return DEFAULT_CONCURRENCY;
  return Math.min(Math.floor(raw), 32);
}

class DiscoveryQueue {
  constructor({ concurrency = readConcurrency(), onSettled = null } = {}) {
    this.concurrency = Math.max(1, Number(concurrency) || DEFAULT_CONCURRENCY);
    this.onSettled = onSettled;
    this.inFlight = new Map(); // key -> promise
    this.pending = [];         // [{ key, run, resolve, reject }]
    this.active = 0;
    this.peak = 0;
    this.stats = { started: 0, coalesced: 0, completed: 0, failed: 0 };
  }

  // Run `task` under the bound. A repeat call for a key already running or queued
  // returns that same promise, so the caller still gets a result without a second
  // SSH session.
  run(key, task) {
    const id = String(key);
    const existing = this.inFlight.get(id);
    if (existing) {
      this.stats.coalesced += 1;
      return existing;
    }
    let resolveOuter;
    let rejectOuter;
    const promise = new Promise((resolve, reject) => { resolveOuter = resolve; rejectOuter = reject; });
    this.inFlight.set(id, promise);
    this.pending.push({ key: id, task, resolve: resolveOuter, reject: rejectOuter });
    this.#pump();
    return promise;
  }

  #pump() {
    while (this.active < this.concurrency && this.pending.length) {
      const job = this.pending.shift();
      this.active += 1;
      this.peak = Math.max(this.peak, this.active);
      this.stats.started += 1;
      Promise.resolve()
        .then(() => job.task())
        .then(
          (value) => { this.stats.completed += 1; job.resolve(value); },
          (err) => { this.stats.failed += 1; job.reject(err); },
        )
        .finally(() => {
          this.active -= 1;
          this.inFlight.delete(job.key);
          if (this.onSettled) {
            try { this.onSettled(job.key); } catch { /* observer must not break the queue */ }
          }
          this.#pump();
        });
    }
  }

  // Keys currently executing (not merely queued).
  get inFlightCount() { return this.active; }

  snapshot() {
    return {
      in_flight: this.active,
      queued: this.pending.length,
      concurrency: this.concurrency,
      peak: this.peak,
      ...this.stats,
    };
  }

  has(key) { return this.inFlight.has(String(key)); }
}

module.exports = { DiscoveryQueue, readConcurrency, DEFAULT_CONCURRENCY };
