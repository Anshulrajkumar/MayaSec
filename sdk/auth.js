import { sendEvent } from './transport.js';

export function startAuthInterception(sessionId, apiKey) {
  // Add listener in the CAPTURE phase (true) so MayaSec intercepts the event
  // BEFORE the bank's own JavaScript gets a chance to see it!
  document.addEventListener('submit', (e) => {
    
    // Check if this looks like a login form (contains a password field)
    const passwordFields = e.target.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      
      // Gather all text inputs to scan
      const inputs = e.target.querySelectorAll('input[type="text"], input[type="password"], input:not([type])');
      
      // Basic RegEx to catch common SQL Injection strings
      const sqlInjectionPattern = /(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP)\b|['";]--|' OR 1=1)/i;
      
      for (let input of inputs) {
        if (sqlInjectionPattern.test(input.value)) {
          // MALICIOUS PAYLOAD DETECTED!
          
          // 1. Block the form from submitting
          e.preventDefault();
          // 2. Stop SecureBank's own JavaScript from running!
          e.stopImmediatePropagation();
          
          // 3. Visual warning for the Hackathon demo
          alert("MAYASEC FIREWALL: Malicious SQL Injection blocked!");
          
          // 4. Send high-priority alert to the Command Center
          sendEvent({
            type: 'SECURITY_ALERT',
            sessionId: sessionId,
            apiKey: apiKey,
            data: {
              reason: 'SQL_INJECTION_ATTEMPT',
              maliciousInput: input.value,
              formAction: e.target.action || window.location.pathname
            },
            timestamp: Date.now()
          });
          
          return; // Stop processing further inputs
        }
      }
      
      // If it's safe, just silently log the attempt
      sendEvent({
        type: 'login_attempt',
        sessionId: sessionId,
        apiKey: apiKey,
        timestamp: Date.now()
      });
    }
  }, true); // <- The 'true' activates the capture phase!
}
