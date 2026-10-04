# INCIDENT REPORT 01
## Repeat Invalid SSH Authentication Attempts

### Incident Overview
5 or more invalid SSH authentication attempts detected to the same VM using invalid usernames from the same source IP address within a 10 minute window. This may indicate SSH brute force activity or username enumeration; however, no successful login was detected afterward.

Case assigned to: Zein Abulkarim

#### Attack information:
* IP address: "SOURCE_IP_FROM_INCIDENT"
* Number of failed authentication attempts: 9
* Unique usernames used: [fakeuser1, fakeuser2, fakeuser3, fakeuser4]

#### Investigation
* Reviewed the alert in Microsoft Sentinel.
* Confirmed 9 invalid-user SSH attempts originated from the same source IP.
* Four unique invalid usernames were observed.
* Queried SSH authentication activity associated with the source IP.
* No successful SSH authentication from the source IP was identified during the investigated period.
* No other suspicious authentication activity was identified.

### Summary
* Incident Title: Fake user SSH login detection
* Unique Incident Number: 1
* Severity: Medium
* MITRE ATT&CK: T1110 - Brute Force
* Incident Creation Time: 05/08/2026 02:00:01(UTC), 06:00:01(Local)
* Status: Closed

### Conclusion
The alert was a true detection of suspicious authentication behaviour, but the activity was generated as part of a lab simulation. No successful authentication or additional suspicious SSH activity was identified. The incident was therefore closed as Benign Positive – Suspicious but Expected.