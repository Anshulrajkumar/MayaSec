import { hashString } from './utils.js';

/**
 * Device fingerprint collection for MayaSec.
 */
export class FingerprintService {
  collectBrowser() {
    const userAgent = navigator.userAgent;
    let name = 'Unknown';

    if (userAgent.includes('Edg')) name = 'Edge';
    else if (userAgent.includes('Chrome')) name = 'Chrome';
    else if (userAgent.includes('Firefox')) name = 'Firefox';
    else if (userAgent.includes('Safari')) name = 'Safari';

    return { name, userAgent };
  }

  collectDevice() {
    return {
      platform: navigator.platform,
      screenWidth: window.screen.width,
      screenHeight: window.screen.height,
      colorDepth: window.screen.colorDepth,
      memory: navigator.deviceMemory || 'unknown',
      hardwareConcurrency: navigator.hardwareConcurrency || 'unknown'
    };
  }

  collectSignals() {
    return {
      browser: this.collectBrowser(),
      device: this.collectDevice(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language || 'unknown',
      cookieEnabled: navigator.cookieEnabled,
      webdriver: Boolean(navigator.webdriver)
    };
  }

  generateFingerprint() {
    const signals = this.collectSignals();
    const raw = JSON.stringify(signals);

    return {
      id: `fp-${hashString(raw)}`,
      ...signals
    };
  }
}

export const fingerprintService = new FingerprintService();

export function generateFingerprint() {
  return fingerprintService.generateFingerprint();
}
