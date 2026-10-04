# Incident Report 7
## Title: Multiple Failed Login Attempts

### Incident Overview
Detects when there are 5 or more failed login attempts into a windows machine from the same source IP address within 10 minutes

Case assigned to: Zein Abdulkarim

#### Attack Information:
* Host: vm-windows-dete
* Ip: SOURCE_IP_FROM_INCIDENT
* LogInAttempts: 176, 177, 124, 178, 36, 133
* TargetAccounts: lenovo, Administrator, user1, admin, admin1, 
* LogonTypes: 3 - Network
* FaliureCodes: 0xc000006d / 0xc0000064, 0x80090308 / 0x0

#### AI-Assisted Analysis


1. **Incident Assessment**  
   The incident involves multiple failed login attempts targeting a Windows host (`vm-windows-dete`) from the same source IP (`SOURCE_IP_FROM_INCIDENT`). Over 10 minutes, the IP attempted to log in to accounts such as `Administrator`, `admin`, `admin1`, `lenovo`, and `user1`, with some accounts receiving over 60 failed attempts. The failure codes `0xc000006d` and `0xc0000064` suggest authentication errors, but their exact meaning is not explicitly provided. While the activity aligns with potential brute-force or credential stuffing attempts (MITRE T1110), no evidence confirms successful access. The severity is **Medium**, as the pattern indicates a potential threat but lacks confirmation of compromise.

2. **Important Timeline Findings**  
   - **2026-09-09 15:01:17**: First failed logon attempt (1 attempt) from `SOURCE_IP_FROM_INCIDENT`.  
   - **15:01:20–15:04:59**: 65 failed attempts targeting `Administrator` (IP: `SOURCE_IP_FROM_INCIDENT`).  
   - **15:05:03–15:06:14**: 22 failed attempts targeting `Administrator`.  
   - **15:06:17–15:09:58**: 66 failed attempts targeting `admin`.  
   - **15:11:13–15:14:59**: 68 failed attempts targeting `admin1`.  
   - **15:21:01–15:24:57**: 70 failed attempts targeting `lenovo`.  
   - **15:25:58–15:29:56**: 71 failed attempts targeting `user1`.  
   - **15:30:00–15:30:53**: 16 failed attempts targeting `user1`.  
   The IP consistently targeted multiple accounts, with some accounts receiving over 60 failed attempts. All events are network-based logons (Event ID 4625). No successful logons or other suspicious activity (e.g., lateral movement, persistence) are observed in the provided data.

3. **Recommended Investigation Steps**  
   - Verify if the IP `SOURCE_IP_FROM_INCIDENT` is associated with known malicious activity or compromised systems.  
   - Check if the targeted accounts (`Administrator`, `admin`, `admin1`, `lenovo`, `user1`) have weak passwords or are publicly exposed.  
   - Investigate if any of the failed attempts were followed by successful logons (e.g., Event ID 4624) within the same timeframe.  
   - Examine logs for additional suspicious activity (e.g., unusual network traffic, file modifications) from the same IP or accounts.  
   - Confirm the meaning of failure codes `0xc000006d` and `0xc0000064` to determine if they indicate specific vulnerabilities or misconfigurations.  

4. **Recommended Response Actions**  
   - Temporarily block the IP `SOURCE_IP_FROM_INCIDENT` using a firewall or intrusion prevention system (IPS) to prevent further attempts.  
   - Enable account lockout policies for the targeted accounts to mitigate brute-force risks.  
   - Review and strengthen passwords for the affected accounts, especially privileged ones like `Administrator`.  
   - Monitor for additional attempts from the same IP or related IPs in the coming hours.  
   - Consider implementing multi-factor authentication (MFA) for critical accounts.  

5. **Missing or Uncertain Information**  
   - The exact meaning of failure codes `0xc000006d` and `0xc0000064` is not provided in the data.  
   - No evidence confirms whether any of the failed attempts were successful (e.g., no Event ID 4624 or other indicators of access).  
   - The source of the IP `SOURCE_IP_FROM_INCIDENT` (e.g., legitimate user, attacker, or compromised system) is unknown.  
   - No information is provided about the host's security posture (e.g., patch levels, configured account lockout policies).

#### Investigation Performed
* Reviewed the authentication activity associated with source IP `SOURCE_IP_FROM_INCIDENT`.
* Identified repeated failed authentication attempts targeting multiple usernames, including accounts that do not exist on the VM.
* Reviewed authentication events surrounding the incident for evidence of successful access from the same source IP.
* No successful authentication from `SOURCE_IP_FROM_INCIDENT` was identified in the reviewed telemetry. Successful logons observed during the surrounding period originated from trusted IP addresses.
* No evidence of successful unauthorized access was identified during the investigation.

### Summary:
* Incident Title: Multiple Failed Login Attempts
* Unique ID: 10
* Severity: Medium
* Mitre Techniques: ["T1110","T1110.001"]
* Status: Closed
* First activity: 2026-09-09 15:03:17+00:00
* Last activity: 2026-09-09 15:30:53+00:00
* Incident ID: ba240e05-419e-4dad-9806-2c99cfd994b9

### Conclusion
The alert showed a true detection of an unkown IP address trying to access the windows VM, against multiple usernames, including accounts that do not exist on the system. This may indicate brute force password guessing and/or username enumeration. The investigation following the attack proved that the IP address did not manage to make a successfull authentication, and there was no successfull logon from any suspicious IP addresses. Incident closed as True Positive - Suspicious activity, but no evidence of compormise was found and no further investigtion required. 