import { getConfig } from './config.js';
import { getEventHistory, subscribe, unsubscribe } from './events.js';
import { logger } from './logger.js';

/**
 * Event transport that flushes standardized events to the backend.
 */
export class TransportService {
  constructor() {
    this.queue = [];
    this.subscriptionId = null;
    this.flushTimer = null;
  }

  start() {
    if (this.subscriptionId) return;
    this.queue.push(...getEventHistory().slice().reverse());
    this.subscriptionId = subscribe((event) => {
      if (event.category === 'transport') return;
      this.queue.push(event);
    });

    this.flushTimer = setInterval(() => {
      this.flush().catch((error) => {
        logger.error('Failed to flush events', error);
      });
    }, getConfig().flushIntervalMs);
    
    // Perform initial check on load
    this.checkInitialStatus();
  }

  stop() {
    if (this.subscriptionId) {
      unsubscribe(this.subscriptionId);
      this.subscriptionId = null;
    }

    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  resolveEndpoint() {
    const config = getConfig();
    if (config.endpoint) return config.endpoint;

    const scripts = document.getElementsByTagName('script');
    let backendUrl = 'https://mayasec.onrender.com';
    for (const script of scripts) {
      if (script.src.includes('/sdk/index.js')) {
        backendUrl = new URL(script.src).origin;
        break;
      }
    }

    return `${backendUrl}/api/ingest`;
  }

  async flush() {
    if (this.queue.length === 0) return;

    const config = getConfig();
    const payload = {
      apiKey: config.apiKey,
      websiteId: config.websiteId || config.appId || '',
      origin: window.location.origin,
      events: this.queue.splice(0, this.queue.length)
    };

    const endpoint = this.resolveEndpoint();

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true
      });
      
      if (res.ok || res.status === 403) {
        const response = await res.json();
        if (response && response.action === 'TIMEOUT') {
          this.triggerTimeout(response.duration || 300000);
        }
      }
    } catch (error) {
      logger.error('Transport failed, re-queueing events');
      this.queue.unshift(...payload.events);
      // fail silently so it retries later
    }
  }
  async checkInitialStatus() {
    try {
      const endpoint = this.resolveEndpoint().replace('/ingest', '/status');
      const res = await fetch(endpoint, { method: 'GET' });
      if (res.status === 403) {
        const response = await res.json();
        if (response && response.action === 'TIMEOUT') {
          this.triggerTimeout(response.duration || 300000);
        }
      }
    } catch(err) {
      // fail silently on network error
    }
  }

  triggerTimeout(duration) {
    if (this._renderInterval) clearInterval(this._renderInterval);
    if (this._countdownInterval) clearInterval(this._countdownInterval);

    let timeRemaining = Math.ceil(duration / 1000);
    
    const requiredCss = `position: fixed !important; top: 0 !important; left: 0 !important; width: 100vw !important; height: 100vh !important; background: rgba(0, 0, 0, 0.85) !important; z-index: 2147483647 !important; display: flex !important; flex-direction: column !important; align-items: center !important; justify-content: center !important; color: white !important; font-family: sans-serif !important; backdrop-filter: blur(8px) !important; opacity: 1 !important; visibility: visible !important; pointer-events: auto !important; margin: 0 !important; padding: 0 !important; transform: none !important;`;

    const enforceOverlay = () => {
      if (timeRemaining <= 0) return;
      
      let overlay = document.getElementById('mayasec-timeout-overlay');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'mayasec-timeout-overlay';
        overlay.innerHTML = `
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px;">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
          <h1 style="margin:0 0 10px 0; font-size:24px;">Security Alert</h1>
          <p style="margin:0 0 20px 0; font-size:16px; color:#cbd5e1; max-width:400px; text-align:center;">
            Unusual activity detected. Your session has been temporarily locked to protect this site.
          </p>
          <div style="font-size:14px; font-weight:bold; background:#ef4444; padding:8px 16px; border-radius:4px;">
            Time remaining: <span id="mayasec-timeout-timer">${timeRemaining}</span>s
          </div>
        `;
        document.body.appendChild(overlay);
      }
      
      // Aggressively re-apply CSS to defeat DevTools tampering (display:none, opacity:0, etc)
      overlay.style.cssText = requiredCss;
    };

    enforceOverlay();
    
    // Aggressive DOM/CSS enforcement loop (100ms)
    this._renderInterval = setInterval(() => {
      if (timeRemaining > 0) enforceOverlay();
    }, 100);
    
    // Timer countdown loop (1000ms)
    this._countdownInterval = setInterval(() => {
      timeRemaining--;
      if (timeRemaining <= 0) {
        clearInterval(this._renderInterval);
        clearInterval(this._countdownInterval);
        const overlay = document.getElementById('mayasec-timeout-overlay');
        if (overlay && document.body.contains(overlay)) {
          document.body.removeChild(overlay);
        }
      } else {
        const timerSpan = document.getElementById('mayasec-timeout-timer');
        if (timerSpan) timerSpan.innerText = timeRemaining;
      }
    }, 1000);
  }
}

export const transportService = new TransportService();
