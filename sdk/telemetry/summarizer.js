export function calculateDistance(points) {
  let distance = 0;
  for (let i = 1; i < points.length; i++) {
    const dx = points[i].x - points[i - 1].x;
    const dy = points[i].y - points[i - 1].y;
    distance += Math.sqrt(dx * dx + dy * dy);
  }
  return distance;
}

export function generateBehaviourSummary(buffer, sessionStats) {
  const mouseEvents = buffer.mouse || [];
  const clickEvents = buffer.clicks || [];
  const scrollEvents = buffer.scrolls || [];

  // Extract points for distance calculation
  const points = mouseEvents
    .filter(e => e.metadata && typeof e.metadata.x === 'number' && typeof e.metadata.y === 'number')
    .map(e => ({ x: e.metadata.x, y: e.metadata.y, t: new Date(e.timestamp).getTime() }));

  const mouseDistance = Math.round(calculateDistance(points));
  
  let averageVelocity = 0;
  let maxVelocity = 0;

  if (points.length > 1) {
    let totalVelocity = 0;
    let velocityCount = 0;
    
    for (let i = 1; i < points.length; i++) {
      const dt = (points[i].t - points[i - 1].t) / 1000; // time in seconds
      if (dt > 0) {
        const dx = points[i].x - points[i - 1].x;
        const dy = points[i].y - points[i - 1].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const velocity = dist / dt;
        
        totalVelocity += velocity;
        velocityCount++;
        if (velocity > maxVelocity) maxVelocity = velocity;
      }
    }
    
    if (velocityCount > 0) {
      averageVelocity = Math.round(totalVelocity / velocityCount);
    }
  }

  maxVelocity = Math.round(maxVelocity);

  return {
    event: 'BEHAVIOUR_SUMMARY',
    mouseDistance,
    averageVelocity,
    maxVelocity,
    clickCount: clickEvents.length,
    scrollCount: scrollEvents.length,
    idleTime: sessionStats.idleTime || 0,
    activeTime: sessionStats.activeTime || 0,
    focusChanges: sessionStats.focusChanges || 0,
    behaviourScore: sessionStats.behaviourScore || 100,
    confidence: sessionStats.confidence || '95%'
  };
}
