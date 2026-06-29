/**
 * SDK configuration storage for MayaSec.
 */

const defaultConfig = {
  apiKey: null,
  appId: null,
  endpoint: null,
  debug: false,
  environment: 'development'
};

let currentConfig = { ...defaultConfig };

/**
 * Stores SDK configuration values.
 *
 * @param {Partial<typeof defaultConfig>} config Configuration overrides.
 * @returns {void}
 */
export function setConfig(config = {}) {
  currentConfig = {
    ...currentConfig,
    ...config
  };
}

/**
 * Returns the current SDK configuration.
 *
 * @returns {typeof defaultConfig} Current SDK configuration.
 */
export function getConfig() {
  return { ...currentConfig };
}

