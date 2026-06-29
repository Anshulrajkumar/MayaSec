export async function sendEvent(payload) {
  // Auto-detect the MayaSec backend URL based on where this script was loaded from
  const scripts = document.getElementsByTagName('script');
  let backendUrl = 'http://localhost:5000'; // Local fallback
  for (let script of scripts) {
    if (script.src.includes('/sdk/index.js')) {
      backendUrl = new URL(script.src).origin;
      break;
    }
  }
  
  const endpoint = `${backendUrl}/api/ingest`;
  
  try {
    // Try sendBeacon for non-blocking send, fallback to fetch
    if (navigator.sendBeacon) {
      const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
      navigator.sendBeacon(endpoint, blob);
    } else {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true
      });
    }
  } catch (err) {
    console.error('MayaSec SDK: Failed to send event', err);
  }
}
