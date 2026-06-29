import { startTracking, getEventsAndClear } from './behaviour.js';
import { generateFingerprint } from './fingerprint.js';
import { sendEvent } from './transport.js';
import { startAuthInterception } from './auth.js';

export const MayaSec = {
  sessionId: null,
  intervalId: null,
  apiKey: null,

  init(config = {}) {
    this.apiKey = config.apiKey || null;
    console.log('MayaSec SDK initialized');
    const fingerprint = generateFingerprint();
    this.sessionId = fingerprint.id;
    
    // Send initial fingerprint
    sendEvent({
      type: 'session_start',
      sessionId: this.sessionId,
      apiKey: this.apiKey,
      data: fingerprint,
      timestamp: Date.now()
    });
  },

  start() {
    startTracking();
    startAuthInterception(this.sessionId, this.apiKey);
    
    const self = this;
    // Flush events every 3 seconds
    this.intervalId = setInterval(() => {
      const events = getEventsAndClear();
      if (events.length > 0) {
        sendEvent({
          type: 'behavior_batch',
          sessionId: self.sessionId,
          apiKey: self.apiKey,
          events: events,
          timestamp: Date.now()
        });
      }
    }, 3000);
    console.log('MayaSec SDK started monitoring');
  },

  stop() {
    clearInterval(this.intervalId);
    console.log('MayaSec SDK stopped');
  },

  version() {
    return '1.0.0';
  },

  destroy() {
    this.stop();
  }
};

if (typeof window !== 'undefined') {
  window.MayaSec = MayaSec;
}

export default MayaSec;
