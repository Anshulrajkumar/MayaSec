import { getConfig } from './config.js';
import { getEventHistory, subscribe, unsubscribe } from './events.js';
import { logger } from './logger.js';

/**
 * Event transport that flushes standardized events to the backend.
 */
export class TransportService {
  constructor() {
    this.queue = [];
    this.subscriptionId = null;
    this.flushTimer = null;
  }

  start() {
    if (this.subscriptionId) return;
    this.queue.push(...getEventHistory().slice().reverse());
    this.subscriptionId = subscribe((event) => {
      if (event.category === 'transport') return;
      this.queue.push(event);
    });

    this.flushTimer = setInterval(() => {
      this.flush().catch((error) => {
        logger.error('Failed to flush events', error);
      });
    }, getConfig().flushIntervalMs);
  }

  stop() {
    if (this.subscriptionId) {
      unsubscribe(this.subscriptionId);
      this.subscriptionId = null;
    }

    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  resolveEndpoint() {
    const config = getConfig();
    if (config.endpoint) return config.endpoint;

    const scripts = document.getElementsByTagName('script');
    let backendUrl = 'https://mayasec.onrender.com';
    for (const script of scripts) {
      if (script.src.includes('/sdk/index.js')) {
        backendUrl = new URL(script.src).origin;
        break;
      }
    }

    return `${backendUrl}/api/ingest`;
  }

  async flush() {
    if (this.queue.length === 0) return;

    const config = getConfig();
    const payload = {
      apiKey: config.apiKey,
      websiteId: config.websiteId || config.appId || '',
      origin: window.location.origin,
      events: this.queue.splice(0, this.queue.length)
    };

    const endpoint = this.resolveEndpoint();

    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
        navigator.sendBeacon(endpoint, blob);
        return;
      }

      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true
      });
    } catch (error) {
      logger.error('Transport failed, re-queueing events');
      this.queue.unshift(...payload.events);
      throw error;
    }
  }
}

export const transportService = new TransportService();
