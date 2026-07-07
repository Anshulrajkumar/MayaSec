import { generateBehaviourSummary } from './summarizer.js';

class SessionStats {
  constructor() {
    this.reset();
  }

  reset() {
    this.startTime = Date.now();
    this.lastActivityTime = Date.now();
    this.activeTime = 0;
    this.idleTime = 0;
    this.focusChanges = 0;
    this.pagesVisited = 0;
    this.apiRequests = 0;
    this.errors = 0;
    this.behaviourScore = 100;
    this.deviceTrustScore = 100;
  }

  update(buffer) {
    const now = Date.now();
    
    // Simple active/idle tracking
    if (buffer.mouse.length > 0 || buffer.clicks.length > 0 || buffer.scrolls.length > 0) {
      this.activeTime += (now - this.lastActivityTime) / 1000;
      this.lastActivityTime = now;
    } else {
      this.idleTime += (now - this.lastActivityTime) / 1000;
    }

    this.apiRequests += buffer.api.length;
    
    const focusEvents = buffer.behaviour.filter(e => e.type === 'FOCUS' || e.type === 'BLUR');
    this.focusChanges += focusEvents.length;
  }
}

export const sessionStats = new SessionStats();

export function aggregateEvents(buffer) {
  // Update session stats with the current buffer
  sessionStats.update(buffer);

  // Generate behaviour summary
  const summaryData = generateBehaviourSummary(buffer, sessionStats);
  
  // Format as a standard event payload
  const summaryEvent = {
    category: 'telemetry',
    event: 'BEHAVIOUR_SUMMARY',
    severity: 'LOW',
    metadata: summaryData
  };

  return summaryEvent;
}
