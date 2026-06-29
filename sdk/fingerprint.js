/**
 * Browser fingerprint collection logic for the MayaSec SDK.
 */

export function collectBrowser() {
  const ua = navigator.userAgent;
  let name = 'Unknown';
  if (ua.includes('Chrome')) name = 'Chrome';
  else if (ua.includes('Firefox')) name = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) name = 'Safari';
  else if (ua.includes('Edge')) name = 'Edge';

  return { name, userAgent: ua };
}

export function collectDevice() {
  return {
    platform: navigator.platform,
    screenWidth: window.screen.width,
    screenHeight: window.screen.height,
    colorDepth: window.screen.colorDepth,
    memory: navigator.deviceMemory || 'unknown'
  };
}

export function collectTimezone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

export function collectLanguage() {
  return navigator.language || navigator.userLanguage;
}

export function generateFingerprint() {
  const browser = collectBrowser();
  const device = collectDevice();
  const timezone = collectTimezone();
  const language = collectLanguage();
  
  // Simple hash of attributes to create a unique ID
  const rawId = `${browser.name}-${device.screenWidth}x${device.screenHeight}-${timezone}-${language}`;
  let hash = 0;
  for (let i = 0; i < rawId.length; i++) {
    const char = rawId.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const id = `fp-${Math.abs(hash).toString(16)}`;

  return { id, browser, device, timezone, language };
}
