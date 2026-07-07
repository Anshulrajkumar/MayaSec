/**
 * SDK configuration storage for MayaSec.
 */

const defaultConfig = {
  apiKey: null,
  appId: null,
  endpoint: null,
  debug: false,
  environment: 'production',
  websiteId: null,
  flushIntervalMs: 3000,
  maxEventHistory: 250,
  behaviourAlertThreshold: 10,
  rapidClickThreshold: 8,
  sessionIdleTimeoutMs: 30 * 60 * 1000,
  sessionStorageKey: 'mayasec:session',
  sessionActivityKey: 'mayasec:last-activity',
  aggregationInterval: 5000,
  maxBufferSize: 1000,
  enableSessionReplay: true,
  lowPriorityRetention: 5000,
  batchSize: 100
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

  return getConfig();
}

/**
 * Returns the current SDK configuration.
 *
 * @returns {typeof defaultConfig} Current SDK configuration.
 */
export function getConfig() {
  return { ...currentConfig };
}

export { defaultConfig };
