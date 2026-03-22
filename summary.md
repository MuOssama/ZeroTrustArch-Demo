# Zero Trust Architecture (ZTA) - Interaction Summary

This document illustrates how the Zero Trust Architecture operates through the interactions between Alice (Admin), Bob (User), and the ZTA System. In a Zero Trust model, the core philosophy is **"Never Trust, Always Verify."**

## The Entities

*   **Alice:** An Administrator using a highly trusted corporate device (`device_001`).
*   **Bob:** A Standard User using a medium-trust personal or secondary device (`device_002`).
*   **The System (ZTA):** The central authority that continuously authenticates, authorizes, and monitors all requests based on dynamic risk assessment.

---

## How the System Operates

### 1. Identity Verification & Device Fingerprinting (Authentication)
When Alice or Bob attempt to log in:
*   **The System** does not simply check their username and password. It also inspects the unique fingerprint of the device they are using.
*   **The System** knows that Alice should be connecting from `device_001` and Bob from `device_002`.
*   If Bob successfully provides his correct password but attempts to log in from an unknown device, the **System** will reject the login attempt.
*   If successful, the **System** issues a time-limited, session-specific token that must be presented with every subsequent request.

### 2. Least Privilege Access (Role-Based Permissions)
The **System** enforces strict boundaries based on roles:
*   **Bob** is granted the `user` role, which strictly allows him to **read** and **create** general data.
*   **Alice** is granted the `admin` role, which allows her to **read**, **create**, **delete**, and **manage users** (access the admin panel).
*   If **Bob** attempts to access the admin panel, the **System** immediately blocks the action at the boundary because his role lacks the explicit permission, logging a security warning.

### 3. Continuous Security Validation
Unlike traditional security where a logged-in user is implicitly trusted to roam the network, the **System** verifies *every single action* taken by Alice and Bob.
*   When **Bob** asks to read data, he presents his token.
*   The **System** unpacks the token, verifies it hasn't expired, and double-checks that his device ID still matches his profile.

### 4. Dynamic Risk Assessment
Before fulfilling *any* allowed request (even if the role permits it), the **System** calculates a real-time **Risk Score** (from 0 to 100) based on multiple contextual factors:
*   **User Privilege:** Highly privileged actions inherently carry more risk.
*   **Device Trust Level:** Alice's high-trust device lowers the risk score. Bob's medium-trust device naturally carries a slightly higher baseline risk. An unknown device spikes the risk score significantly.
*   **Action Sensitivity:** A simple read request carries low risk. Deleting data or managing users carries massive risk.
*   **Time of Access:** The system expects users to operate within standard business hours (e.g., 8 AM - 6 PM). 

**Example Scenarios:**
*   **Scenario A:** **Alice** tries to manage users from her trusted device during business hours. The risk is considered acceptable, and the **System** allows it.
*   **Scenario B:** **Bob** attempts to write data from his medium-trust device at 2:00 AM. Because the time of access falls far outside standard business hours, the **System** forcefully elevates the risk score for this specific action.
*   If the calculated risk score exceeds the maximum acceptable threshold (e.g., 70 out of 100), the **System** dynamically denies the request—*even if Bob had a valid token and the correct role for writing data.* 

## Conclusion

In this architecture, the **System** assumes breach and trusts no one by default. **Bob** and **Alice** must continually prove not only *who* they are, but *what* they are using, *when* they are acting, and *how* risky their intent is, forcing every single data interaction to pass through rigorous, real-time security checkpoints.
