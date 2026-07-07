import { getConfig } from '../config.js';
import { logger } from '../logger.js';
import { emitEvent as coreEmit } from '../events.js'; // The bus emitter
import { telemetryBuffer } from './buffer.js';
import { aggregateEvents, sessionStats } from './aggregator.js';
import { clearAggregatedEvents } from './retention.js';
import { PRIORITY_LEVELS } from './priority.js';

class TelemetrySender {
  constructor() {
    this.timer = null;
  }

  start() {
    const config = getConfig();
    const interval = config.aggregationInterval || 5000;
    
    if (this.timer) clearInterval(this.timer);
    
    this.timer = setInterval(() => {
      this.flushBatch();
    }, interval);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
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

  async sendPayload(events) {
    if (events.length === 0) return;

    const config = getConfig();
    const payload = {
      apiKey: config.apiKey,
      websiteId: config.websiteId || config.appId || '',
      origin: window.location.origin,
      events: events
    };

    try {
      await fetch(this.resolveEndpoint(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true
      });
    } catch (error) {
      logger.error('Failed to send telemetry payload', error);
      // Optional: Handle re-queueing here if needed
    }
  }

  flushBatch() {
    const buf = telemetryBuffer.getBuffer();
    
    // Only aggregate and send if there's actual activity
    const hasActivity = buf.mouse.length > 0 || buf.clicks.length > 0 || buf.scrolls.length > 0 || buf.medium.length > 0;
    
    if (!hasActivity) return;

    // 1. Aggregate low priority events into a summary
    const summaryEvent = aggregateEvents(buf);
    
    // Convert summary to a proper security event via bus
    const finalSummary = coreEmit(summaryEvent);

    // 2. Collect session stats (can be appended to summary or sent separately, here we include it in the batch)
    const statsEvent = coreEmit({
      category: 'telemetry',
      event: 'SESSION_STATISTICS',
      severity: 'LOW',
      metadata: { ...sessionStats }
    });

    // 3. Prepare payload: Summary + Stats + Medium Events + API Events
    const batch = [
      finalSummary,
      statsEvent,
      ...buf.medium,
      ...buf.api
    ];

    // 4. Clear low priority events from buffer
    clearAggregatedEvents();
    
    // Clear medium and api events
    buf.medium = [];
    buf.api = [];

    // 5. Transmit
    this.sendPayload(batch);
  }

  sendImmediate(event) {
    // High priority events are sent immediately without waiting for the batch
    this.sendPayload([event]);
  }
}

export const telemetrySender = new TelemetrySender();
