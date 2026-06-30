import { emitEvent } from './events.js';
import { sessionManager } from './session.js';
import { serializeError } from './utils.js';

/**
 * Browser API and XHR interception.
 */
export class ApiMonitor {
  constructor() {
    this.originalFetch = null;
    this.originalXHROpen = null;
    this.originalXHRSend = null;
    this.started = false;
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.hookFetch();
    this.hookXHR();
  }

  stop() {
    if (this.originalFetch) {
      window.fetch = this.originalFetch;
      this.originalFetch = null;
    }

    if (this.originalXHROpen) {
      XMLHttpRequest.prototype.open = this.originalXHROpen;
      this.originalXHROpen = null;
    }

    if (this.originalXHRSend) {
      XMLHttpRequest.prototype.send = this.originalXHRSend;
      this.originalXHRSend = null;
    }

    this.started = false;
  }

  hookFetch() {
    if (typeof window.fetch !== 'function' || this.originalFetch) return;
    this.originalFetch = window.fetch.bind(window);

    window.fetch = async (input, init = {}) => {
      const sessionId = sessionManager.getSession()?.id || '';
      const url = typeof input === 'string' ? input : input?.url;
      const method = init.method || (typeof input === 'object' && 'method' in input ? input.method : 'GET');

      emitEvent({
        sessionId,
        category: 'api',
        event: 'API_REQUEST',
        severity: 'LOW',
        metadata: { transport: 'fetch', url, method }
      });

      try {
        const response = await this.originalFetch(input, init);
        emitEvent({
          sessionId,
          category: 'api',
          event: 'API_RESPONSE',
          severity: response.ok ? 'LOW' : 'MEDIUM',
          metadata: { transport: 'fetch', url, method, status: response.status, ok: response.ok }
        });
        return response;
      } catch (error) {
        emitEvent({
          sessionId,
          category: 'api',
          event: 'API_ERROR',
          severity: 'HIGH',
          metadata: { transport: 'fetch', url, method, error: serializeError(error) }
        });
        throw error;
      }
    };
  }

  hookXHR() {
    if (this.originalXHROpen || this.originalXHRSend) return;
    this.originalXHROpen = XMLHttpRequest.prototype.open;
    this.originalXHRSend = XMLHttpRequest.prototype.send;

    const monitor = this;

    XMLHttpRequest.prototype.open = function mayaSecOpen(method, url, ...rest) {
      this.__mayaSecMeta = { method, url };
      return monitor.originalXHROpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function mayaSecSend(body) {
      const sessionId = sessionManager.getSession()?.id || '';
      const meta = this.__mayaSecMeta || { method: 'GET', url: 'unknown' };

      emitEvent({
        sessionId,
        category: 'api',
        event: 'API_REQUEST',
        severity: 'LOW',
        metadata: { transport: 'xhr', ...meta, hasBody: Boolean(body) }
      });

      this.addEventListener('loadend', () => {
        emitEvent({
          sessionId,
          category: 'api',
          event: this.status >= 400 ? 'API_ERROR' : 'API_RESPONSE',
          severity: this.status >= 400 ? 'HIGH' : 'LOW',
          metadata: { transport: 'xhr', ...meta, status: this.status }
        });
      });

      return monitor.originalXHRSend.call(this, body);
    };
  }
}

export const apiMonitor = new ApiMonitor();

export function hookFetch() {
  apiMonitor.hookFetch();
}

export function hookXHR() {
  apiMonitor.hookXHR();
}

export function unhook() {
  apiMonitor.stop();
}
