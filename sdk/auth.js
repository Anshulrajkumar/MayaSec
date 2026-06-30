import { emitEvent } from './events.js';
import { sessionManager } from './session.js';

const SQL_INJECTION_PATTERN = /(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP)\b|['";]--|' OR 1=1)/i;

/**
 * Authentication monitoring and login interception.
 */
export class AuthMonitor {
  constructor() {
    this.started = false;
    this.failedAttempts = 0;
    this.handler = this.handleSubmit.bind(this);
  }

  start() {
    if (this.started) return;
    this.started = true;
    document.addEventListener('submit', this.handler, true);
  }

  stop() {
    if (!this.started) return;
    document.removeEventListener('submit', this.handler, true);
    this.started = false;
  }

  /**
   * @param {SubmitEvent} event
   * @returns {void}
   */
  handleSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return;

    const sessionId = sessionManager.getSession()?.id || '';
    const inputs = Array.from(form.querySelectorAll('input[type="text"], input[type="password"], input[type="email"], input:not([type])'));

    emitEvent({
      sessionId,
      category: 'auth',
      event: 'LOGIN_ATTEMPT',
      severity: 'LOW',
      risk: 5,
      metadata: {
        formAction: form.action || window.location.pathname,
        inputCount: inputs.length
      }
    });

    for (const input of inputs) {
      if (!SQL_INJECTION_PATTERN.test(input.value)) continue;

      event.preventDefault();
      event.stopImmediatePropagation();

      this.failedAttempts += 1;
      alert('MAYASEC FIREWALL: Malicious SQL Injection blocked!');

      emitEvent({
        sessionId,
        category: 'security',
        event: 'SQL_INJECTION',
        severity: 'CRITICAL',
        risk: 80,
        metadata: {
          value: input.value,
          formAction: form.action || window.location.pathname,
          failedAttemptCount: this.failedAttempts
        }
      });

      emitEvent({
        sessionId,
        category: 'auth',
        event: 'LOGIN_FAILED',
        severity: 'HIGH',
        risk: 10,
        metadata: {
          reason: 'SQL_INJECTION_ATTEMPT',
          failedAttemptCount: this.failedAttempts
        }
      });

      return;
    }

    emitEvent({
      sessionId,
      category: 'auth',
      event: 'LOGIN_SUCCESS',
      severity: 'LOW',
      metadata: {
        formAction: form.action || window.location.pathname
      }
    });
  }
}

export const authMonitor = new AuthMonitor();

export function startAuthInterception() {
  authMonitor.start();
}
