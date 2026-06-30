import { broadcastService } from '../dashboard/broadcastService.js';
import { eventNormalizer } from '../events/eventNormalizer.js';
import { eventStore } from '../events/eventStore.js';
import { riskEngine } from './riskEngine.js';
import { rulesEngine } from './rulesEngine.js';
import { siteRegistryService } from '../services/siteRegistryService.js';

/**
 * End-to-end event processing pipeline.
 */
export class EventPipeline {
  constructor() {
    this.sessionIndex = new Map();
  }

  /**
   * @param {Array<Record<string, unknown>>} events
   * @param {{ hostname: string, origin: string, apiKey: string, websiteId: string }} context
   * @returns {{ normalizedEvents: Array<Record<string, unknown>>, derivedEvents: Array<Record<string, unknown>>, sites: Array<Record<string, unknown>> }}
   */
  processBatch(events, context) {
    const normalizedEvents = [];
    const derivedEvents = [];
    let isCritical = false;

    for (const event of events) {
      const normalized = eventNormalizer.normalize(event, context);
      const sessionEvents = this.getSessionEvents(normalized.sessionId);
      const risk = riskEngine.apply(normalized);
      normalized.riskScore = risk.score;
      normalized.riskLevel = risk.level;
      
      if (risk.level === 'CRITICAL') isCritical = true;

      this.storeSessionEvent(normalized);
      eventStore.save(normalized);
      normalizedEvents.push(normalized);
      broadcastService.broadcast('new_event', normalized, context.apiKey);
      siteRegistryService.record(context);

      const generated = rulesEngine.process(normalized, { sessionEvents: this.getSessionEvents(normalized.sessionId) });
      generated.forEach((derived) => {
        const derivedRisk = riskEngine.apply(derived);
        derived.riskScore = derivedRisk.score;
        derived.riskLevel = derivedRisk.level;
        
        if (derivedRisk.level === 'CRITICAL') isCritical = true;
        
        this.storeSessionEvent(derived);
        eventStore.save(derived);
        derivedEvents.push(derived);
        broadcastService.broadcast('new_event', derived, context.apiKey);
      });
    }

    const sites = siteRegistryService.listByApiKey(context.apiKey);
    broadcastService.broadcast('sites_update', sites, context.apiKey);
    return { normalizedEvents, derivedEvents, sites, isCritical };
  }

  /**
   * @param {string} sessionId
   * @returns {Array<Record<string, unknown>>}
   */
  getSessionEvents(sessionId) {
    return this.sessionIndex.get(sessionId) || [];
  }

  /**
   * @param {Record<string, unknown>} event
   * @returns {void}
   */
  storeSessionEvent(event) {
    const events = this.sessionIndex.get(event.sessionId) || [];
    events.push(event);
    if (events.length > 250) events.shift();
    this.sessionIndex.set(event.sessionId, events);
  }
}

export const eventPipeline = new EventPipeline();
