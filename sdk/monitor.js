import { emitEvent } from './events.js';
import { sessionManager } from './session.js';
import { debounce, serializeError } from './utils.js';

/**
 * Browser security monitor for developer tools, JS errors, and DOM mutations.
 */
export class BrowserMonitor {
  constructor() {
    this.started = false;
    this.intervalId = null;
    this.mutationObserver = null;
    this.cspHandler = null;
    this.errorHandler = this.handleError.bind(this);
    this.rejectionHandler = this.handleRejection.bind(this);
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.detectDevTools();
    this.monitorErrors();
    this.monitorDOMChanges();
    this.monitorCspViolations();
  }

  stop() {
    if (this.intervalId) clearInterval(this.intervalId);
    if (this.mutationObserver) this.mutationObserver.disconnect();
    window.removeEventListener('error', this.errorHandler, true);
    window.removeEventListener('unhandledrejection', this.rejectionHandler, true);
    if (this.cspHandler) document.removeEventListener('securitypolicyviolation', this.cspHandler, true);
    this.started = false;
  }

  detectDevTools() {
    let emitted = false;
    this.intervalId = setInterval(() => {
      const widthGap = window.outerWidth - window.innerWidth > 160;
      const heightGap = window.outerHeight - window.innerHeight > 160;
      if (!emitted && (widthGap || heightGap)) {
        emitted = true;
        emitEvent({
          sessionId: sessionManager.getSession()?.id || '',
          category: 'monitor',
          event: 'DEVTOOLS_OPENED',
          severity: 'MEDIUM',
          risk: 15,
          metadata: {
            widthGap,
            heightGap
          }
        });
      }
    }, 1500);
  }

  monitorErrors() {
    window.addEventListener('error', this.errorHandler, true);
    window.addEventListener('unhandledrejection', this.rejectionHandler, true);
  }

  handleError(event) {
    emitEvent({
      sessionId: sessionManager.getSession()?.id || '',
      category: 'monitor',
      event: 'JS_ERROR',
      severity: 'MEDIUM',
      metadata: {
        message: event.message,
        filename: event.filename,
        line: event.lineno,
        column: event.colno
      }
    });
  }

  handleRejection(event) {
    emitEvent({
      sessionId: sessionManager.getSession()?.id || '',
      category: 'monitor',
      event: 'JS_ERROR',
      severity: 'MEDIUM',
      metadata: {
        rejection: serializeError(event.reason)
      }
    });
  }

  monitorDOMChanges() {
    const emitMutation = debounce((count) => {
      emitEvent({
        sessionId: sessionManager.getSession()?.id || '',
        category: 'monitor',
        event: 'DOM_MUTATION',
        severity: 'LOW',
        metadata: { mutationCount: count }
      });
    }, 1000);

    this.mutationObserver = new MutationObserver((mutations) => {
      const suspicious = mutations.some((mutation) => Array.from(mutation.addedNodes).some((node) => node.nodeName === 'SCRIPT'));

      emitMutation(mutations.length);

      if (suspicious) {
        emitEvent({
          sessionId: sessionManager.getSession()?.id || '',
          category: 'monitor',
          event: 'SCRIPT_INJECTION',
          severity: 'HIGH',
          metadata: {
            mutationCount: mutations.length
          }
        });
      }
    });

    this.mutationObserver.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  monitorCspViolations() {
    this.cspHandler = (event) => {
      emitEvent({
        sessionId: sessionManager.getSession()?.id || '',
        category: 'monitor',
        event: 'CSP_VIOLATION',
        severity: 'HIGH',
        metadata: {
          blockedURI: event.blockedURI,
          violatedDirective: event.violatedDirective
        }
      });
    };

    document.addEventListener('securitypolicyviolation', this.cspHandler, true);
  }
}

export const browserMonitor = new BrowserMonitor();

export function detectDevTools() {
  browserMonitor.detectDevTools();
}

export function monitorErrors() {
  browserMonitor.monitorErrors();
}

export function monitorDOMChanges() {
  browserMonitor.monitorDOMChanges();
}

export function monitorConsole() {
  return undefined;
}
