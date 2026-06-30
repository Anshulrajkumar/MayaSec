import { defaultRules } from '../rules/defaultRules.js';

/**
 * Server-side rules engine for normalized events.
 */
export class RulesEngine {
  constructor(rules = defaultRules) {
    this.rules = rules;
  }

  /**
   * @param {Record<string, unknown>} event
   * @param {{ sessionEvents: Array<Record<string, unknown>> }} context
   * @returns {Array<Record<string, unknown>>}
   */
  process(event, context) {
    return this.rules.flatMap((rule) => {
      const result = rule.evaluate(event, context);
      if (!result) return [];

      return [{
        id: `derived_${rule.id}_${event.id}`,
        sessionId: event.sessionId,
        websiteId: event.websiteId,
        timestamp: new Date().toISOString(),
        category: 'alert',
        event: result.event,
        severity: result.severity || rule.severity,
        risk: result.score ?? rule.score,
        metadata: {
          ruleId: rule.id,
          ruleName: rule.name,
          description: rule.description,
          action: result.action,
          sourceEventId: event.id
        },
        type: result.event,
        origin: event.origin,
        location: event.location,
        data: {
          ruleId: rule.id,
          reason: result.event,
          details: rule.description,
          confidence: result.severity === 'HIGH' ? 'High (95%)' : 'Medium (80%)'
        },
        _apiKey: event._apiKey
      }, {
        id: `alert_${rule.id}_${event.id}`,
        sessionId: event.sessionId,
        websiteId: event.websiteId,
        timestamp: new Date().toISOString(),
        category: 'alert',
        event: 'SECURITY_ALERT',
        severity: result.severity || rule.severity,
        risk: result.score ?? rule.score,
        metadata: {
          ruleId: rule.id,
          action: result.action,
          sourceEvent: result.event
        },
        type: 'SECURITY_ALERT',
        origin: event.origin,
        location: event.location,
        data: {
          reason: result.event,
          details: rule.description,
          confidence: result.severity === 'HIGH' ? 'High (95%)' : 'Medium (80%)'
        },
        _apiKey: event._apiKey
      }];
    });
  }
}

export const rulesEngine = new RulesEngine();
