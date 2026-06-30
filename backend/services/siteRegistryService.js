/**
 * Tracks known monitored sites for the dashboard.
 */
export class SiteRegistryService {
  constructor() {
    this.connectedSites = new Map();
  }

  /**
   * @param {{ hostname: string, origin: string, apiKey: string }} context
   * @returns {{ name: string, url: string, apiKey: string, eventCount: number, lastSeen: number, firstSeen: number }}
   */
  record(context) {
    const key = `${context.hostname}_${context.apiKey}`;
    if (!this.connectedSites.has(key)) {
      this.connectedSites.set(key, {
        name: context.hostname,
        url: context.origin,
        apiKey: context.apiKey,
        eventCount: 0,
        lastSeen: Date.now(),
        firstSeen: Date.now()
      });
    }

    const site = this.connectedSites.get(key);
    site.eventCount += 1;
    site.lastSeen = Date.now();
    return site;
  }

  /**
   * @param {string} apiKey
   * @returns {Array<Record<string, unknown>>}
   */
  listByApiKey(apiKey) {
    return Array.from(this.connectedSites.values()).filter((site) => site.apiKey === apiKey);
  }
}

export const siteRegistryService = new SiteRegistryService();
