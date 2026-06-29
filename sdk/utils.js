/**
 * Shared utility placeholders for the MayaSec SDK.
 */

/**
 * Generates a basic UUID value.
 *
 * @returns {string} UUID value.
 */
export function generateUUID() {
  return crypto.randomUUID();
}

/**
 * Returns the current Unix timestamp in milliseconds.
 *
 * @returns {number} Current timestamp.
 */
export function timestamp() {
  return Date.now();
}

/**
 * Produces a placeholder hash value.
 *
 * @param {unknown} value Value to hash later.
 * @returns {string} Placeholder hash output.
 */
export function hash(value) {
  return `mock-hash:${String(value)}`;
}

/**
 * Creates a placeholder debounced function wrapper.
 *
 * @param {Function} callback Function to wrap.
 * @returns {Function} Wrapped function.
 */
export function debounce(callback) {
  return (...args) => callback(...args);
}

/**
 * Creates a placeholder throttled function wrapper.
 *
 * @param {Function} callback Function to wrap.
 * @returns {Function} Wrapped function.
 */
export function throttle(callback) {
  return (...args) => callback(...args);
}

/**
 * Waits for the requested number of milliseconds.
 *
 * @param {number} milliseconds Delay duration.
 * @returns {Promise<void>} Promise that resolves after the delay.
 */
export function sleep(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

