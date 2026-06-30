import { getConfig } from './config.js';
import { storage } from './storage.js';
import { generateUUID, nowIso } from './utils.js';

/**
 * Session lifecycle management for the MayaSec SDK.
 */
export class SessionManager {
  constructor() {
    this.session = null;
  }

  /**
   * @returns {{ id: string, startedAt: string, lastActivityAt: string, expiresAt: string, active: boolean, durationMs: number }}
   */
  startOrRestoreSession() {
    const config = getConfig();
    const now = Date.now();
    const stored = storage.get(config.sessionStorageKey, null);

    if (stored && new Date(stored.expiresAt).getTime() > now) {
      this.session = {
        ...stored,
        active: true,
        lastActivityAt: nowIso(),
        durationMs: Math.max(0, now - new Date(stored.startedAt).getTime())
      };
      this.persist();
      return this.getSession();
    }

    this.session = this.createSession();
    this.persist();
    return this.getSession();
  }

  /**
   * @returns {ReturnType<SessionManager['startOrRestoreSession']>}
   */
  createSession() {
    const config = getConfig();
    const startedAt = nowIso();
    return {
      id: `ms_sess_${generateUUID()}`,
      startedAt,
      lastActivityAt: startedAt,
      expiresAt: new Date(Date.now() + config.sessionIdleTimeoutMs).toISOString(),
      active: true,
      durationMs: 0
    };
  }

  /**
   * @returns {ReturnType<SessionManager['startOrRestoreSession']>|null}
   */
  getSession() {
    if (!this.session) return null;

    return {
      ...this.session,
      durationMs: Math.max(0, Date.now() - new Date(this.session.startedAt).getTime())
    };
  }

  /**
   * @returns {void}
   */
  touch() {
    if (!this.session) return;
    const config = getConfig();
    this.session.lastActivityAt = nowIso();
    this.session.expiresAt = new Date(Date.now() + config.sessionIdleTimeoutMs).toISOString();
    this.persist();
  }

  /**
   * @returns {void}
   */
  expireSession() {
    const config = getConfig();
    storage.remove(config.sessionStorageKey);
    this.session = null;
  }

  /**
   * @returns {boolean}
   */
  isActive() {
    if (!this.session) return false;
    return new Date(this.session.expiresAt).getTime() > Date.now();
  }

  persist() {
    const config = getConfig();
    storage.set(config.sessionStorageKey, this.session);
    storage.set(config.sessionActivityKey, this.session?.lastActivityAt || null);
  }
}

export const sessionManager = new SessionManager();
