/**
 * Browser storage wrappers for the MayaSec SDK.
 */

/**
 * Saves a value to localStorage.
 *
 * @param {string} key Storage key.
 * @param {unknown} value Serializable value.
 * @returns {void}
 */
export function save(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

/**
 * Loads a value from localStorage.
 *
 * @param {string} key Storage key.
 * @returns {unknown} Parsed stored value, or null when unavailable.
 */
export function load(key) {
  const value = localStorage.getItem(key);
  return value ? JSON.parse(value) : null;
}

/**
 * Removes a value from localStorage.
 *
 * @param {string} key Storage key.
 * @returns {void}
 */
export function remove(key) {
  localStorage.removeItem(key);
}

/**
 * Clears localStorage.
 *
 * @returns {void}
 */
export function clear() {
  localStorage.clear();
}

