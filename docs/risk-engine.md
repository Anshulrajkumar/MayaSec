# MayaSec Risk Engine Architecture

## 1. Overall Scoring Methodology
The MayaSec Risk Engine transitions from a static, arbitrary scoring system to a dynamic, cumulative risk model aligned with commercial SIEMs (Security Information and Event Management) and WAFs. 

Instead of triggering absolute threat alerts based on isolated events, MayaSec continuously tracks the risk profile of a user session. The final threat score is a product of **Risk Score** (how dangerous the action is) and **Confidence** (how certain we are that the action is malicious).

## 2. Risk Calculation & Cumulative Scoring
Each normalized security event contributes a **Weighted Risk Delta** to the session's overall score.
- **Base Score:** Defined in the JSON rule file (0-100).
- **Time Decay:** Older events decay in relevance over time (e.g., losing 10% of their weight per minute of inactivity).
- **Correlation Multiplier:** If multiple distinct rules fire in a short period (e.g., *DevTools Opened* + *Repeated Login Failure*), a correlation multiplier is applied to escalate the risk.

Risk Score levels follow a CVSS-inspired scale:
* **0–24**: LOW
* **25–49**: MEDIUM
* **50–74**: HIGH
* **75–100**: CRITICAL

## 3. Confidence Calculation
Confidence determines the reliability of a detection. It is represented as a percentage (0–100%).
- A single rapid click might have a Base Score of 15 and Confidence of 30% (High chance of false positive).
- Repeated headless browser signatures have a Confidence of 95% (Low false positive).

**Action thresholds** use both metrics:
- *Risk 80 + Confidence 95% = BLOCK*
- *Risk 80 + Confidence 35% = CHALLENGE/REVIEW*

## 4. Time-Based Score Decay & False Positive Mitigation
To prevent users from accumulating a 100/100 score over a long, normal 8-hour session, the engine implements a Time Decay function. Risk points naturally bleed off during periods of normal, non-malicious interaction, mitigating false positives derived from cumulative low-severity events.

## 5. Industry Framework Alignment
All rules must strictly map to recognized cybersecurity frameworks:
- **OWASP Top 10 / ASVS:** Web application vulnerability mapping.
- **OWASP Automated Threats (OAT):** Bot and credential stuffing classification.
- **MITRE ATT&CK:** Adversarial tactics and techniques mapping.
- **MITRE CAPEC:** Attack pattern taxonomy.
- **NIST CSF:** Incident response classification.

No arbitrary labels are used; everything ties back to standard taxonomies.
