/**
 * Shared utilities for the MayaSec SDK.
 */

/**
 * Generates a UUID with a browser-safe fallback.
 *
 * @returns {string}
 */
export function generateUUID() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  return `ms-${Math.random().toString(16).slice(2)}-${Date.now().toString(16)}`;
}

/**
 * Returns the current time as an ISO timestamp.
 *
 * @returns {string}
 */
export function nowIso() {
  return new Date().toISOString();
}

/**
 * Returns the current time in milliseconds.
 *
 * @returns {number}
 */
export function nowMs() {
  return Date.now();
}

/**
 * Creates a stable hash from a string value.
 *
 * @param {string} value
 * @returns {string}
 */
export function hashString(value) {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = ((hash << 5) - hash) + value.charCodeAt(index);
    hash |= 0;
  }

  return Math.abs(hash).toString(16);
}

/**
 * Creates a throttled function wrapper.
 *
 * @template {(...args: any[]) => void} T
 * @param {T} callback
 * @param {number} waitMs
 * @returns {T}
 */
export function throttle(callback, waitMs) {
  let lastRun = 0;

  return /** @type {T} */ ((...args) => {
    const now = nowMs();
    if ((now - lastRun) < waitMs) return;
    lastRun = now;
    callback(...args);
  });
}

/**
 * Creates a debounced function wrapper.
 *
 * @template {(...args: any[]) => void} T
 * @param {T} callback
 * @param {number} waitMs
 * @returns {T}
 */
export function debounce(callback, waitMs) {
  let timeoutId = null;

  return /** @type {T} */ ((...args) => {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => callback(...args), waitMs);
  });
}

/**
 * Returns a normalized hostname for the current page.
 *
 * @returns {string}
 */
export function currentHostname() {
  if (typeof window === 'undefined') return 'unknown';
  return window.location.hostname || 'unknown';
}

/**
 * Safely parses JSON.
 *
 * @param {string|null} value
 * @param {unknown} fallback
 * @returns {unknown}
 */
export function safeJsonParse(value, fallback = null) {
  if (!value) return fallback;

  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

/**
 * Builds a shallow serializable error payload.
 *
 * @param {unknown} error
 * @returns {{ message: string, stack?: string }}
 */
export function serializeError(error) {
  if (error instanceof Error) {
    return {
      message: error.message,
      stack: error.stack
    };
  }

  return {
    message: String(error)
  };
}
