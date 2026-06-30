import { defaultRiskProfile } from '../risk/defaultRiskProfile.js';

/**
 * Server-side session risk aggregation.
 */
export class RiskEngine {
  constructor(profile = defaultRiskProfile) {
    this.profile = profile;
    this.sessionScores = new Map();
  }

  /**
   * @param {Record<string, unknown>} event
   * @returns {{ score: number, level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL' }}
   */
  apply(event) {
    const current = this.sessionScores.get(event.sessionId) || 0;
    const delta = typeof event.risk === 'number' ? event.risk : (this.profile[event.event] || 0);
    const score = current + delta;
    const risk = {
      score,
      level: score >= 90 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW'
    };
    this.sessionScores.set(event.sessionId, score);
    return risk;
  }
}

export const riskEngine = new RiskEngine();
