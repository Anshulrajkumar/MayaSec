import { emitEvent } from './events.js';

const SQL_INJECTION_PATTERN = /(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP)\b|['";]--|' OR 1=1)/i;

/**
 * Centralized rules engine for browser detections.
 */
export class RulesEngine {
  constructor() {
    this.rules = [
      {
        id: 'sql-injection',
        name: 'SQL Injection',
        description: 'Detects SQL injection payloads in submitted inputs.',
        severity: 'CRITICAL',
        score: 80,
        evaluate(event) {
          const value = String(event.metadata?.value || '');
          if (!value || !SQL_INJECTION_PATTERN.test(value)) return null;
          return { action: 'BLOCK', event: 'SQL_INJECTION', severity: 'CRITICAL', score: 80 };
        }
      },
      {
        id: 'rapid-clicking',
        name: 'Rapid Clicking',
        description: 'Detects repeated clicking in a short time window.',
        severity: 'HIGH',
        score: 25,
        evaluate(event) {
          if (event.event !== 'CLICK_ACTIVITY') return null;
          const clickCount = Number(event.metadata?.recentClickCount || 0);
          if (clickCount < 8) return null;
          return { action: 'WARN', event: 'RAPID_CLICKING', severity: 'HIGH', score: 25 };
        }
      },
      {
        id: 'headless-browser',
        name: 'Headless Browser',
        description: 'Flags webdriver or headless browser indicators.',
        severity: 'HIGH',
        score: 50,
        evaluate(event) {
          if (event.event !== 'SESSION_STARTED') return null;
          if (!event.metadata?.fingerprint?.webdriver) return null;
          return { action: 'WARN', event: 'HEADLESS_BROWSER', severity: 'HIGH', score: 50 };
        }
      },
      {
        id: 'zero-mouse-movement',
        name: 'Zero Mouse Movement',
        description: 'Flags click activity without mouse movement.',
        severity: 'MEDIUM',
        score: 20,
        evaluate(event) {
          if (event.event !== 'CLICK_ACTIVITY') return null;
          if (Number(event.metadata?.mouseEventCount || 0) > 0) return null;
          return { action: 'WARN', event: 'BOT_ACTIVITY', severity: 'MEDIUM', score: 20 };
        }
      },
      {
        id: 'devtools-opened',
        name: 'Developer Tools Opened',
        description: 'Flags browser developer tools usage.',
        severity: 'MEDIUM',
        score: 15,
        evaluate(event) {
          if (event.event !== 'DEVTOOLS_OPENED') return null;
          return { action: 'WARN', event: 'DEVTOOLS_OPENED', severity: 'MEDIUM', score: 15 };
        }
      },
      {
        id: 'repeated-login-failure',
        name: 'Repeated Login Failure',
        description: 'Flags repeated failed logins in a session.',
        severity: 'HIGH',
        score: 30,
        evaluate(event) {
          if (event.event !== 'LOGIN_FAILED') return null;
          const count = Number(event.metadata?.failedAttemptCount || 0);
          if (count < 3) return null;
          return { action: 'BLOCK', event: 'SUSPICIOUS_BEHAVIOUR', severity: 'HIGH', score: 30 };
        }
      },
      {
        id: 'credential-stuffing',
        name: 'Credential Stuffing',
        description: 'Placeholder for credential stuffing detection.',
        severity: 'CRITICAL',
        score: 75,
        evaluate() {
          return null;
        }
      },
      {
        id: 'impossible-travel',
        name: 'Impossible Travel',
        description: 'Placeholder for impossible travel detection.',
        severity: 'HIGH',
        score: 60,
        evaluate() {
          return null;
        }
      },
      {
        id: 'multiple-device-login',
        name: 'Multiple Device Login',
        description: 'Placeholder for multi-device login detection.',
        severity: 'HIGH',
        score: 45,
        evaluate() {
          return null;
        }
      }
    ];
  }

  /**
   * @param {import('./events.js').SecurityEvent} event
   * @returns {Array<{ id: string, action: 'ALLOW'|'WARN'|'BLOCK'|'DECEIVE', event: string, severity: string, score: number, description: string, name: string }>}
   */
  evaluate(event) {
    return this.rules.flatMap((rule) => {
      const result = rule.evaluate(event);
      if (!result) return [];

      return [{
        id: rule.id,
        name: rule.name,
        description: rule.description,
        action: result.action || 'ALLOW',
        event: result.event,
        severity: result.severity || rule.severity,
        score: result.score ?? rule.score
      }];
    });
  }

  /**
   * Emits security alerts for matched rules.
   *
   * @param {import('./events.js').SecurityEvent} event
   * @returns {void}
   */
  process(event) {
    const matches = this.evaluate(event);

    matches.forEach((match) => {
      emitEvent({
        sessionId: event.sessionId,
        websiteId: event.websiteId,
        category: 'security',
        event: match.event,
        severity: match.severity,
        risk: match.score,
        metadata: {
          ruleId: match.id,
          ruleName: match.name,
          description: match.description,
          action: match.action,
          sourceEventId: event.id,
          sourceEvent: event.event,
          sourceMetadata: event.metadata
        }
      });

      emitEvent({
        sessionId: event.sessionId,
        websiteId: event.websiteId,
        category: 'alert',
        event: 'SECURITY_ALERT',
        severity: match.severity,
        risk: match.score,
        metadata: {
          ruleId: match.id,
          action: match.action,
          sourceEvent: match.event,
          details: match.description
        }
      });
    });
  }
}

export const rulesEngine = new RulesEngine();
