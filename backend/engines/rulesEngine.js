import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load all JSON rules
const rulesDir = path.join(__dirname, '../rules');
const ruleFiles = ['authentication.json', 'behaviour.json', 'browser.json', 'api.json', 'network.json', 'owasp.json', 'mitre.json', 'deception.json'];
const allRules = [];

for (const file of ruleFiles) {
  try {
    const data = fs.readFileSync(path.join(rulesDir, file), 'utf8');
    const rules = JSON.parse(data);
    allRules.push(...rules);
  } catch (err) {
    console.warn(`[RulesEngine] Could not load rule file ${file}`);
  }
}

/**
 * Server-side rules engine evaluating standardized JSON detection rules.
 */
export class RulesEngine {
  constructor(rules = allRules) {
    this.rules = rules;
  }

  /**
   * @param {Record<string, unknown>} event
   * @param {{ sessionEvents: Array<Record<string, unknown>> }} context
   * @returns {Array<Record<string, unknown>>}
   */
  process(event, context) {
    return this.rules.flatMap((rule) => {
      if (!rule.detection) return [];
      
      const { targetEvent, threshold, timeWindow, condition } = rule.detection;
      
      // We only evaluate if the current event matches the rule's target event
      if (event.event !== targetEvent) return [];
      
      let matched = false;
      const recentEvents = timeWindow > 0 
        ? context.sessionEvents.filter(e => e.event === targetEvent && (new Date(event.timestamp).getTime() - new Date(e.timestamp).getTime() <= timeWindow * 1000))
        : context.sessionEvents.filter(e => e.event === targetEvent);

      if (condition === 'count') {
        // Trigger exactly when threshold is reached or multiples of it
        if (recentEvents.length > 0 && recentEvents.length % threshold === 0) {
          matched = true;
        }
      } else if (condition === 'no_mouse_movement') {
        const moves = context.sessionEvents.filter((item) => item.event === 'MOUSE_ACTIVITY');
        if (moves.length === 0 && recentEvents.length > 0 && recentEvents.length % threshold === 0) {
          matched = true;
        }
      } else if (condition === 'webdriver_true') {
        if (event.metadata?.fingerprint?.webdriver) {
          matched = true;
        }
      }

      if (!matched) return [];

      return [{
        id: `derived_${rule.id}_${event.id}`,
        sessionId: event.sessionId,
        websiteId: event.websiteId,
        timestamp: new Date().toISOString(),
        category: 'alert',
        event: rule.action === 'BLOCK' || rule.action === 'CHALLENGE' ? 'SECURITY_ALERT' : 'SUSPICIOUS_BEHAVIOUR',
        severity: rule.severity,
        risk: rule.baseScore,
        confidence: rule.confidence,
        metadata: {
          ruleId: rule.id,
          ruleName: rule.name,
          framework: rule.framework,
          description: rule.description,
          action: rule.action,
          sourceEventId: event.id
        },
        type: rule.action === 'BLOCK' || rule.action === 'CHALLENGE' ? 'SECURITY_ALERT' : 'SUSPICIOUS_BEHAVIOUR',
        origin: event.origin,
        location: event.location,
        data: {
          ruleId: rule.id,
          reason: rule.name,
          details: rule.description,
          confidence: `${rule.confidence}%`
        },
        _apiKey: event._apiKey
      }];
    });
  }
}

export const rulesEngine = new RulesEngine();
