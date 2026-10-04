# INCIDENT REPORT 05
## Successful SSH Authentication Following Repeated Invalid Attempts

### Incident Overview
A successful SSH authentication event was detected within 15 minutes after 5 or more invalid SSH authentication attempts using invalid usernames from the same source IP address. This may indicate SSH brute force activity or username enumeration.
The incident came in after an early warning that detected the failed SSH authentication attempts before the successful attempt. The early-warning incident report can be found in [Incident Report 04](./IncidentReport04).


Case assigned to: Zein Abulkarim

#### Attack information:
* IP address: "SOURCE_IP_FROM_INCIDENT"
* Number of failed authentication attempts: 6
* Unique usernames used: [fakeuser3, fakeuser2, fakeuser1]
* Authentication method: publickey
* Authenticated user: azureuser
* Success source port: 5322
* First failure at 2026-08-05 21:56:13(UTC)
* Last failure at 2026-08-05 22:02:17(UTC)
* Success at 2026-08-05 22:02:25(UTC)


#### Investigation
* Reviewed the alert in Microsoft Sentinel.
* Confirmed that one successful authentication followed 6 invalid-user SSH attempts from the same source IP.
* Three unique invalid usernames were observed.
* Queried all collected Syslog activity containing the source IP within specific time window.
* No additional suspicious activity was identified.

### Summary
* Incident Title: Successful authentication after multiple failed attempts
* Unique Incident Number: 5
* Severity: High
* MITRE ATT&CK: T1110 - Brute Force
* Incident Creation Time: 05/08/2026, 22:11:55(UTC), 06/08/2026 02:11:55(Local)
* Status: Closed

### Conclusion
The alert was a true detection of repeated, suspicious authentication activity followed by successful authentication from the same source IP. The activity was generated as part of a lab simulation to test the query after minor changes. The updated query successfully identified and correlated the simulated activity as expected. This incident was closed as Benign Positive – Suspicious but Expected.