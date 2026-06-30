/**
 * Maps incoming SDK events into the canonical MayaSec event shape while
 * preserving legacy dashboard fields.
 */
export class EventNormalizer {
  /**
   * @param {Record<string, unknown>} event
   * @param {{ hostname: string, websiteId: string, apiKey: string }} context
   * @returns {Record<string, unknown>}
   */
  normalize(event, context) {
    const metadata = event.metadata || {};
    const normalized = {
      id: event.id || `evt_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`,
      sessionId: event.sessionId || 'unknown-session',
      websiteId: event.websiteId || context.websiteId || context.hostname,
      timestamp: event.timestamp || new Date().toISOString(),
      category: event.category || 'security',
      event: event.event || event.type || 'UNKNOWN_EVENT',
      severity: event.severity || 'LOW',
      risk: typeof event.risk === 'number' ? event.risk : 0,
      metadata,
      type: event.type || event.event || 'UNKNOWN_EVENT',
      origin: context.hostname,
      ip: context.clientIp || 'Unknown',
      location: metadata.location || context.hostname,
      data: metadata,
      _apiKey: context.apiKey
    };

    if (normalized.event === 'SESSION_STARTED') {
      normalized.type = 'session_start';
    }

    if (normalized.event === 'LOGIN_ATTEMPT') {
      normalized.type = 'login_attempt';
    }

    if (['MOUSE_ACTIVITY', 'CLICK_ACTIVITY', 'SCROLL_ACTIVITY', 'KEYBOARD_ACTIVITY'].includes(normalized.event)) {
      normalized.type = normalized.event;
    }

    return normalized;
  }
}

export const eventNormalizer = new EventNormalizer();
