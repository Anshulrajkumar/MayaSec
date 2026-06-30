/**
 * Server-side derived detection rules.
 */
export const defaultRules = [
  {
    id: 'rapid-clicking',
    name: 'Rapid Clicking',
    description: 'Detects sustained click bursts that indicate bot behavior.',
    severity: 'HIGH',
    score: 25,
    evaluate(event, context) {
      if (event.event !== 'CLICK_ACTIVITY') return null;
      const sessionEvents = context.sessionEvents.filter((item) => item.event === 'CLICK_ACTIVITY');
      if (sessionEvents.length < 8) return null;
      return { action: 'WARN', event: 'RAPID_CLICKING', severity: 'HIGH', score: 25 };
    }
  },
  {
    id: 'zero-mouse-movement',
    name: 'Zero Mouse Movement',
    description: 'Detects click activity without accompanying mouse movement.',
    severity: 'MEDIUM',
    score: 20,
    evaluate(event, context) {
      if (event.event !== 'CLICK_ACTIVITY') return null;
      const sessionMoves = context.sessionEvents.filter((item) => item.event === 'MOUSE_ACTIVITY');
      if (sessionMoves.length > 0) return null;
      return { action: 'WARN', event: 'BOT_ACTIVITY', severity: 'MEDIUM', score: 20 };
    }
  },
  {
    id: 'headless-browser',
    name: 'Headless Browser',
    description: 'Detects webdriver-enabled fingerprint sessions.',
    severity: 'HIGH',
    score: 50,
    evaluate(event) {
      if (event.event !== 'SESSION_STARTED') return null;
      if (!event.metadata?.fingerprint?.webdriver) return null;
      return { action: 'WARN', event: 'HEADLESS_BROWSER', severity: 'HIGH', score: 50 };
    }
  },
  {
    id: 'repeated-login-failure',
    name: 'Repeated Login Failure',
    description: 'Detects repeated failed login activity.',
    severity: 'HIGH',
    score: 30,
    evaluate(event, context) {
      if (event.event !== 'LOGIN_FAILED') return null;
      const failures = context.sessionEvents.filter((item) => item.event === 'LOGIN_FAILED');
      if (failures.length < 3) return null;
      return { action: 'BLOCK', event: 'SUSPICIOUS_BEHAVIOUR', severity: 'HIGH', score: 30 };
    }
  }
];
