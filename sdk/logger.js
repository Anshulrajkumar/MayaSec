/**
 * Lightweight browser console logging wrapper for the MayaSec SDK.
 */

/**
 * Logs an informational message.
 *
 * @param {...unknown} args Values to log.
 * @returns {void}
 */
export function info(...args) {
  console.info(...args);
}

/**
 * Logs a warning message.
 *
 * @param {...unknown} args Values to log.
 * @returns {void}
 */
export function warn(...args) {
  console.warn(...args);
}

/**
 * Logs an error message.
 *
 * @param {...unknown} args Values to log.
 * @returns {void}
 */
export function error(...args) {
  console.error(...args);
}

/**
 * Logs a debug message.
 *
 * @param {...unknown} args Values to log.
 * @returns {void}
 */
export function debug(...args) {
  console.debug(...args);
}

