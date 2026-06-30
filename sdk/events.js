import { getConfig } from './config.js';
import { logger } from './logger.js';
import { generateUUID, nowIso } from './utils.js';

/**
 * @typedef {Object} SecurityEvent
 * @property {string} id
 * @property {string} sessionId
 * @property {string} websiteId
 * @property {string} timestamp
 * @property {string} category
 * @property {string} event
 * @property {string} severity
 * @property {number} risk
 * @property {Record<string, unknown>} metadata
 * @property {string} [type]
 */

/**
 * Centralized browser event bus.
 */
export class EventBus {
  constructor() {
    this.listeners = new Map();
    this.history = [];
  }

  /**
   * @param {Partial<SecurityEvent> & { event: string, category?: string, metadata?: Record<string, unknown> }} payload
   * @returns {SecurityEvent}
   */
  emitEvent(payload) {
    const config = getConfig();
    const event = {
      id: payload.id || generateUUID(),
      sessionId: payload.sessionId || '',
      websiteId: payload.websiteId || config.websiteId || config.appId || '',
      timestamp: payload.timestamp || nowIso(),
      category: payload.category || 'security',
      event: payload.event,
      severity: payload.severity || 'LOW',
      risk: typeof payload.risk === 'number' ? payload.risk : 0,
      metadata: payload.metadata || {},
      type: payload.type || payload.event
    };

    this.history.unshift(event);
    if (this.history.length > config.maxEventHistory) {
      this.history.length = config.maxEventHistory;
    }

    for (const listener of this.listeners.values()) {
      try {
        listener(event);
      } catch (error) {
        logger.error('Event listener failed', error);
      }
    }

    return event;
  }

  /**
   * @param {(event: SecurityEvent) => void} listener
   * @returns {string}
   */
  subscribe(listener) {
    const id = generateUUID();
    this.listeners.set(id, listener);
    return id;
  }

  /**
   * @param {string} id
   * @returns {void}
   */
  unsubscribe(id) {
    this.listeners.delete(id);
  }

  /**
   * @returns {SecurityEvent[]}
   */
  getEventHistory() {
    return [...this.history];
  }
}

export const eventBus = new EventBus();
export const emitEvent = eventBus.emitEvent.bind(eventBus);
export const subscribe = eventBus.subscribe.bind(eventBus);
export const unsubscribe = eventBus.unsubscribe.bind(eventBus);
export const getEventHistory = eventBus.getEventHistory.bind(eventBus);
