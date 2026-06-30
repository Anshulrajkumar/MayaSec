/**
 * In-memory event store used for dashboard history and SSE replay.
 */
export class EventStore {
  constructor(limit = 500) {
    this.limit = limit;
    this.events = [];
  }

  /**
   * @param {Record<string, unknown>} event
   * @returns {void}
   */
  save(event) {
    this.events.unshift(event);
    if (this.events.length > this.limit) {
      this.events.length = this.limit;
    }
  }

  /**
   * @param {string} apiKey
   * @returns {Record<string, unknown>[]}
   */
  getByApiKey(apiKey) {
    return this.events.filter((event) => event._apiKey === apiKey);
  }
}

export const eventStore = new EventStore();
