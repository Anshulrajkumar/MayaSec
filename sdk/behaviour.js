import { getConfig } from './config.js';
import { emitEvent } from './events.js';
import { sessionManager } from './session.js';
import { throttle } from './utils.js';

/**
 * Browser behaviour telemetry for MayaSec.
 */
export class BehaviourTracker {
  constructor() {
    this.started = false;
    this.recentClicks = [];
    this.mouseEventCount = 0;
    this.lastAlert = 0;
    this.listeners = [];
  }

  start() {
    if (this.started) return;
    this.started = true;

    this.addListener('mousemove', throttle((event) => {
      this.mouseEventCount += 1;
      this.record('MOUSE_ACTIVITY', {
        x: event.clientX,
        y: event.clientY
      });
    }, 500));

    this.addListener('click', (event) => {
      const now = Date.now();
      this.recentClicks.push(now);
      this.recentClicks = this.recentClicks.filter((timestamp) => (now - timestamp) < 3000);

      this.record('CLICK_ACTIVITY', {
        x: event.clientX,
        y: event.clientY,
        target: event.target?.tagName || 'UNKNOWN',
        recentClickCount: this.recentClicks.length,
        mouseEventCount: this.mouseEventCount
      });

      if (
        this.recentClicks.length >= getConfig().behaviourAlertThreshold &&
        (now - this.lastAlert) > 5000
      ) {
        alert('MAYASEC WARNING: Automated bot behavior (Click Spamming) detected. Please stop.');
        this.lastAlert = now;
      }
    });

    this.addListener('scroll', throttle(() => {
      this.record('SCROLL_ACTIVITY', {
        scrollX: window.scrollX,
        scrollY: window.scrollY
      });
    }, 750));

    this.lastKeyTime = 0;
    this.keyCount = 0;
    this.addListener('keydown', (event) => {
      const now = Date.now();
      const delta = this.lastKeyTime ? now - this.lastKeyTime : 0;
      this.lastKeyTime = now;
      this.keyCount++;

      // Classify key type WITHOUT sending the actual key value
      const keyStr = event.key || '';
      let keyCategory = 'other';
      if (/^[a-zA-Z]$/.test(keyStr)) keyCategory = 'letter';
      else if (/^[0-9]$/.test(keyStr)) keyCategory = 'digit';
      else if (['Shift','Control','Alt','Meta','Tab','CapsLock'].includes(keyStr)) keyCategory = 'modifier';
      else if (['Enter','Backspace','Delete','Escape'].includes(keyStr)) keyCategory = 'control';
      else if (keyStr.length === 1) keyCategory = 'symbol';

      // Check if the user is typing in a sensitive field
      const target = event.target;
      const isSensitive = target && (
        target.type === 'password' ||
        target.type === 'email' ||
        target.autocomplete === 'cc-number' ||
        target.autocomplete === 'cc-csc' ||
        target.name?.toLowerCase().includes('card')
      );

      this.record('KEYBOARD_ACTIVITY', {
        keyCategory,
        sensitiveField: isSensitive,
        timeSinceLastKey: delta,
        totalKeystrokes: this.keyCount
      });
    });
  }

  stop() {
    this.listeners.forEach(({ type, handler }) => {
      document.removeEventListener(type, handler, true);
    });
    this.listeners = [];
    this.started = false;
  }

  addListener(type, handler) {
    document.addEventListener(type, handler, true);
    this.listeners.push({ type, handler });
  }

  record(event, metadata) {
    sessionManager.touch();
    emitEvent({
      sessionId: sessionManager.getSession()?.id || '',
      category: 'behaviour',
      event,
      metadata
    });
  }
}

export const behaviourTracker = new BehaviourTracker();

export function startTracking() {
  behaviourTracker.start();
}
