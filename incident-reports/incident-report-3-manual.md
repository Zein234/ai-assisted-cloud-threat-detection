# INCIDENT REPORT 03
## Successful SSH Authentication Following Repeated Invalid Attempts

### Incident Overview
Two successful SSH authentication events were detected within 15 minutes after 5 or more invalid SSH authentication attempts using invalid usernames from the same source IP address. This may indicate SSH brute force activity or username enumeration.

The incident came in after an early warning that detected the failed SSH authentication attempts before the successful attempt. The early-warning incident report can be found in [Incident Report 02](./IncidentReport02).
The first successful authentication occurred after 7 invalid SSH authentication attempts; the second occurred after an additional 6 invalid SSH attempts, for a total of 13 invalid attempts before the second successful authentication.

Case assigned to: Zein Abulkarim

#### Attack information:
* IP address: "SOURCE_IP_FROM_INCIDENT"
* Number of failed authentication attempts: 7, 13
* Unique usernames used: [fakeuser1, fakeuser2, fakeuser3, fakeuser4]
* Authentication method: publickey
* Authenticated user: azureuser
* Success source port: 56371, 56378
* First failure at 2026-08-05 10:23:19(UTC)
* Last failure before first success at 2026-08-05 10:24:00(UTC)
* First success at 2026-08-05 10:24:06(UTC)
* Last failure before second success at 2026-08-05 10:24:46(UTC)
* Second success at 2026-08-05 10:24:56(UTC)

#### Investigation
* Reviewed the alert in Microsoft Sentinel.
* Confirmed that 2 successful authentications followed a total of 13 invalid-user SSH attempts from the same source IP.
* Four unique invalid usernames were observed.
* Queried all collected Syslog activity containing the source IP within specific time window.
* No additional suspicious activity was identified.

### Summary
* Incident Title: Successful authentication after multiple failed attempts
* Unique Incident Number: 3
* Severity: High
* MITRE ATT&CK: T1110 - Brute Force
* Incident Creation Time: 05/08/2026 10:33:00(UTC), 14:33:00(Local)
* Status: Closed

### Conclusion
The alert was a true detection of repeated, suspicious authentication activity followed by successful authentication from the same source IP. The activity was generated as part of a lab simulation, and this incident was closed as Benign Positive – Suspicious but Expected.