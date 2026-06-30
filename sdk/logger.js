import { getConfig } from './config.js';

/**
 * Lightweight logger for the MayaSec SDK.
 */
export class Logger {
  /**
   * @param {string} namespace
   */
  constructor(namespace = 'MayaSec') {
    this.namespace = namespace;
  }

  /**
   * @param {'debug'|'info'|'warn'|'error'} level
   * @param {...unknown} args
   * @returns {void}
   */
  log(level, ...args) {
    const config = getConfig();
    if (level === 'debug' && !config.debug) return;

    const consoleMethod = console[level] || console.log;
    consoleMethod(`[${this.namespace}]`, ...args);
  }

  debug(...args) {
    this.log('debug', ...args);
  }

  info(...args) {
    this.log('info', ...args);
  }

  warn(...args) {
    this.log('warn', ...args);
  }

  error(...args) {
    this.log('error', ...args);
  }
}

export const logger = new Logger();
