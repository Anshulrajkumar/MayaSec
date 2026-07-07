import { apiMonitor } from './api.js';
import { authMonitor } from './auth.js';
import { behaviourTracker } from './behaviour.js';
import { setConfig, getConfig } from './config.js';
import { emitEvent, subscribe, unsubscribe, getEventHistory } from './events.js';
import { fingerprintService } from './fingerprint.js';
import { logger } from './logger.js';
import { browserMonitor } from './monitor.js';
import { riskEngine } from './risk.js';
import { rulesEngine } from './rules.js';
import { sessionManager } from './session.js';
import { initTelemetryPipeline, stopTelemetryPipeline } from './telemetry/index.js';
import { currentHostname } from './utils.js';

class MayaSecSDK {
  constructor() {
    this.started = false;
    this.rulesSubscriptionId = null;
    this.riskSubscriptionId = null;
  }

  init(config = {}) {
    const resolvedConfig = setConfig({
      ...config,
      websiteId: config.websiteId || config.appId || currentHostname()
    });

    const session = sessionManager.startOrRestoreSession();
    const fingerprint = fingerprintService.generateFingerprint();

    emitEvent({
      sessionId: session.id,
      websiteId: resolvedConfig.websiteId,
      category: 'session',
      event: 'SESSION_STARTED',
      severity: 'LOW',
      metadata: {
        fingerprint,
        session
      }
    });

    emitEvent({
      sessionId: session.id,
      websiteId: resolvedConfig.websiteId,
      category: 'navigation',
      event: 'PAGE_VIEW',
      severity: 'LOW',
      metadata: {
        path: window.location.pathname,
        href: window.location.href,
        title: document.title
      }
    });

    logger.info('SDK initialized', { websiteId: resolvedConfig.websiteId, sessionId: session.id });
    return this;
  }

  start() {
    if (this.started) return;
    this.started = true;

    const history = getEventHistory().slice().reverse();

    this.rulesSubscriptionId = subscribe((event) => {
      if (['SECURITY_ALERT', 'SQL_INJECTION', 'RAPID_CLICKING', 'HEADLESS_BROWSER', 'BOT_ACTIVITY', 'SUSPICIOUS_BEHAVIOUR'].includes(event.event)) {
        return;
      }

      rulesEngine.process(event);
    });

    this.riskSubscriptionId = subscribe((event) => {
      const risk = riskEngine.applyEvent(event);
      if (event.event === 'SECURITY_ALERT') {
        logger.warn('Security alert emitted', { sessionId: event.sessionId, risk });
      }
    });

    history.forEach((event) => {
      if (!['SECURITY_ALERT', 'SQL_INJECTION', 'RAPID_CLICKING', 'HEADLESS_BROWSER', 'BOT_ACTIVITY', 'SUSPICIOUS_BEHAVIOUR'].includes(event.event)) {
        rulesEngine.process(event);
      }
      riskEngine.applyEvent(event);
    });

    initTelemetryPipeline();
    behaviourTracker.start();
    authMonitor.start();
    apiMonitor.start();
    browserMonitor.start();
    sessionManager.touch();

    logger.info('SDK started', getConfig());
  }

  stop() {
    if (!this.started) return;
    this.started = false;

    behaviourTracker.stop();
    authMonitor.stop();
    apiMonitor.stop();
    browserMonitor.stop();
    stopTelemetryPipeline();

    if (this.rulesSubscriptionId) unsubscribe(this.rulesSubscriptionId);
    if (this.riskSubscriptionId) unsubscribe(this.riskSubscriptionId);
    this.rulesSubscriptionId = null;
    this.riskSubscriptionId = null;
  }

  destroy() {
    this.stop();
    sessionManager.expireSession();
  }

  version() {
    return '2.0.0';
  }

  emitEvent(payload) {
    return emitEvent({
      ...payload,
      sessionId: payload.sessionId || sessionManager.getSession()?.id || '',
      websiteId: payload.websiteId || getConfig().websiteId
    });
  }

  subscribe(listener) {
    return subscribe(listener);
  }

  unsubscribe(id) {
    unsubscribe(id);
  }

  getEventHistory() {
    return getEventHistory();
  }
}

export const MayaSec = new MayaSecSDK();

if (typeof window !== 'undefined') {
  window.MayaSec = MayaSec;
}

export default MayaSec;
