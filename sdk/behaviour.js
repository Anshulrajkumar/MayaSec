let events = [];
let lastAlert = 0;

export function startTracking() {
  // Track clicks
  document.addEventListener('click', (e) => {
    events.push({
      type: 'click',
      x: e.clientX,
      y: e.clientY,
      target: e.target.tagName,
      timestamp: Date.now()
    });

    // Client-side visual warning for the Hackathon Demo
    const recentClicks = events.filter(ev => ev.type === 'click' && (Date.now() - ev.timestamp) < 3000);
    if (recentClicks.length >= 10 && (Date.now() - lastAlert) > 5000) {
      alert("🚨 MAYASEC WARNING: Automated bot behavior (Click Spamming) detected! Please stop! 🚨");
      lastAlert = Date.now();
    }
  });

  // Track mouse moves (throttled)
  let lastMove = 0;
  document.addEventListener('mousemove', (e) => {
    const now = Date.now();
    if (now - lastMove > 500) { // Record every 500ms
      events.push({
        type: 'mousemove',
        x: e.clientX,
        y: e.clientY,
        timestamp: now
      });
      lastMove = now;
    }
  });
}

export function getEventsAndClear() {
  const currentEvents = [...events];
  events = []; // Clear for next batch
  return currentEvents;
}
