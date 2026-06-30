/**
 * Cumulative risk scoring for MayaSec sessions.
 */

const EVENT_RISK_WEIGHTS = {
  SESSION_STARTED: 0,
  PAGE_VIEW: 0,
  MOUSE_ACTIVITY: 0,
  SCROLL_ACTIVITY: 0,
  CLICK_ACTIVITY: 0,
  KEYBOARD_ACTIVITY: 0,
  LOGIN_ATTEMPT: 5,
  LOGIN_FAILED: 10,
  RAPID_CLICKING: 25,
  DEVTOOLS_OPENED: 15,
  SQL_INJECTION: 80,
  HEADLESS_BROWSER: 50,
  BOT_ACTIVITY: 40,
  SECURITY_ALERT: 60
};

export class RiskEngine {
  constructor() {
    this.sessionScores = new Map();
  }

  /**
   * @param {import('./events.js').SecurityEvent} event
   * @returns {{ score: number, level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL' }}
   */
  applyEvent(event) {
    const current = this.sessionScores.get(event.sessionId) || 0;
    const delta = event.risk || EVENT_RISK_WEIGHTS[event.event] || 0;
    const score = current + delta;
    const state = {
      score,
      level: this.levelForScore(score)
    };

    this.sessionScores.set(event.sessionId, score);
    return state;
  }

  /**
   * @param {string} sessionId
   * @returns {{ score: number, level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL' }}
   */
  getRisk(sessionId) {
    const score = this.sessionScores.get(sessionId) || 0;
    return {
      score,
      level: this.levelForScore(score)
    };
  }

  /**
   * @param {number} score
   * @returns {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'}
   */
  levelForScore(score) {
    if (score >= 90) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  }
}

export const riskEngine = new RiskEngine();
