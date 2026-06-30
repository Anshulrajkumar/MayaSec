/**
 * Advanced Risk Engine with Time Decay, Cumulative Scoring, and Event Correlation.
 * Maps to CVSS-inspired severity bands.
 */
export class RiskEngine {
  constructor() {
    this.sessionScores = new Map(); // sessionId -> { currentScore: number, lastUpdate: number, eventHistory: [] }
  }

  /**
   * @param {Record<string, unknown>} event
   * @returns {{ score: number, level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL' }}
   */
  apply(event) {
    const now = new Date(event.timestamp || Date.now()).getTime();
    let session = this.sessionScores.get(event.sessionId);
    
    if (!session) {
      session = { currentScore: 0, lastUpdate: now, eventHistory: [] };
    }

    // Time Decay: lose 1% of score for every minute of inactivity
    const timeDiffMinutes = (now - session.lastUpdate) / 60000;
    if (timeDiffMinutes > 0 && session.currentScore > 0) {
      const decayFactor = Math.pow(0.99, timeDiffMinutes); // compound decay
      session.currentScore = session.currentScore * decayFactor;
    }

    // Correlation Multiplier
    // If different rule categories are triggered within 5 mins, escalate
    const recentHistory = session.eventHistory.filter(e => (now - e.timestamp) <= 300000);
    const uniqueCategories = new Set(recentHistory.map(e => e.category)).size;
    const correlationMultiplier = uniqueCategories > 1 ? 1 + (uniqueCategories * 0.1) : 1.0;

    let delta = 0;
    if (event.risk) {
      // Risk is weighted by confidence (if available)
      const confidenceWeight = typeof event.confidence === 'number' ? (event.confidence / 100) : 1.0;
      delta = event.risk * confidenceWeight * correlationMultiplier;
      
      // Log event category for correlation tracking
      session.eventHistory.push({ category: event.metadata?.ruleId?.split('-')[0] || 'GENERAL', timestamp: now });
    } else {
       // Regular generic events have minor static impacts if defined
       // (Left blank or implemented with default profiles if needed)
    }

    session.currentScore += delta;
    
    // Cap at 100
    if (session.currentScore > 100) session.currentScore = 100;
    
    session.lastUpdate = now;

    this.sessionScores.set(event.sessionId, session);

    const score = Math.round(session.currentScore);
    const risk = {
      score,
      level: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW'
    };
    
    return risk;
  }
}

export const riskEngine = new RiskEngine();
