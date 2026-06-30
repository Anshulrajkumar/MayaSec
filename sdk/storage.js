import { safeJsonParse } from './utils.js';

/**
 * Browser storage abstraction used by the MayaSec SDK.
 */
export class StorageService {
  /**
   * @param {Storage|null} storage
   */
  constructor(storage = typeof window !== 'undefined' ? window.localStorage : null) {
    this.storage = storage;
  }

  /**
   * @param {string} key
   * @param {unknown} value
   * @returns {void}
   */
  set(key, value) {
    if (!this.storage) return;
    this.storage.setItem(key, JSON.stringify(value));
  }

  /**
   * @template T
   * @param {string} key
   * @param {T} fallback
   * @returns {T}
   */
  get(key, fallback = /** @type {T} */ (null)) {
    if (!this.storage) return fallback;
    return /** @type {T} */ (safeJsonParse(this.storage.getItem(key), fallback));
  }

  /**
   * @param {string} key
   * @returns {void}
   */
  remove(key) {
    if (!this.storage) return;
    this.storage.removeItem(key);
  }
}

export const storage = new StorageService();
