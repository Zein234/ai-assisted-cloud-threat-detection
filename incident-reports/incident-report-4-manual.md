# INCIDENT REPORT 04
## Repeat Invalid SSH Authentication Attempts

### Incident Overview
5 or more invalid SSH authentication attempts detected to the same VM using invalid usernames from the same source IP address within a 10 minute window. This may indicate SSH brute force activity or username enumeration. This incident came in as an early alert for [Incident 05](./IncidentReport05), which detected a successful SSH authentication from the same IP shortly after the failed attempts.

Case assigned to: Zein Abulkarim

#### Attack information:
* IP address: "SOURCE_IP_FROM_INCIDENT"
* Number of failed authentication attempts: 6
* Unique usernames used: [fakeuser3, fakeuser2, fakeuser1]

#### Investigation
* Reviewed the alert in Microsoft Sentinel.
* Confirmed 6 invalid-user SSH attempts originated from the same source IP.
* Three unique invalid usernames were observed.
* Shortly after, a separate high-severity incident ([Incident 05](./IncidentReport05)) was generated, which detected a successful authentication attempt following a number of failed attempts from the same IP address as the one detected in this incident.
* Further analysis of the successful authentication was therefore handled under [Incident Report 05](./IncidentReport05).

### Summary
* Incident Title: Invalid user SSH login detection
* Unique Incident Number: 4
* Severity: Medium
* MITRE ATT&CK: T1110 - Brute Force
* Incident Creation Time: 05/08/2026 22:09:53(UTC), 06/08/2026 02:09:53(Local)
* Status: Closed

### Conclusion
The alert was a true detection of suspicious authentication behaviour. The alert came through as an early warning of a high-severity alert that detected a successful authentication by that same IP address. The activity was generated as part of a lab simulation to ensure the query still works after minor changes. This incident was closed as Benign Positive – Suspicious but Expected.