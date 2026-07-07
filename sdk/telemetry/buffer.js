import { getConfig } from '../config.js';
import { getEventPriority, PRIORITY_LEVELS } from './priority.js';

class TelemetryBuffer {
  constructor() {
    this.reset();
  }

  reset() {
    this.buffer = {
      mouse: [],
      clicks: [],
      scrolls: [],
      api: [],
      behaviour: [],
      medium: [],
      high: []
    };
  }

  addEvent(event) {
    const config = getConfig();
    const priority = getEventPriority(event.event || event.type);

    if (priority === PRIORITY_LEVELS.HIGH) {
      this.buffer.high.push(event);
      return PRIORITY_LEVELS.HIGH; // Signal to send immediately
    }

    if (priority === PRIORITY_LEVELS.MEDIUM) {
      this.buffer.medium.push(event);
    } else {
      // LOW PRIORITY - group by type for easier aggregation
      const type = event.event || event.type;
      if (type === 'MOUSE_ACTIVITY') {
        this.buffer.mouse.push(event);
      } else if (type === 'CLICK_ACTIVITY') {
        this.buffer.clicks.push(event);
      } else if (type === 'SCROLL_ACTIVITY') {
        this.buffer.scrolls.push(event);
      } else if (type.startsWith('API_')) {
        this.buffer.api.push(event);
      } else {
        this.buffer.behaviour.push(event);
      }
    }
    
    // Prevent unbounded memory growth if sender fails
    this.enforceSizeLimits(config.maxBufferSize || 1000);
    
    return priority;
  }

  enforceSizeLimits(maxSize) {
    for (const key of Object.keys(this.buffer)) {
      if (this.buffer[key].length > maxSize) {
        // Keep the most recent events
        this.buffer[key] = this.buffer[key].slice(-maxSize);
      }
    }
  }

  getBuffer() {
    return this.buffer;
  }
}

export const telemetryBuffer = new TelemetryBuffer();
