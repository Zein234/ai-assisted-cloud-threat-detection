# Incident Report 8
## Title: Windows Registry Run Key Persistence Detected

### Incident Overview
Detects modifications to Windows Run or RunOnce registry keys using Sysmon Event ID 13. These registries can be used to configure programs or commands to execute when a user logs on, providing a persistence mechanism.

Case assigned to: Zein Abdulkarim

#### Attack Information:
* Host: vm-windows-dete
* User: vm-windows-dete\azureuser
* Process: C:\Windows\system32\reg.exe
* RegistryTarget: HKU\S-1-5-21-2259420536-3155087175-3443295236-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\LabPersistence
* RegistryValue: cmd.exe /c echo PersistenceExecuted >> C:\Users\Public\persistence-executed.txt

#### AI-Assisted Analysis
## 1. Incident Assessment
**Classification: likely benign — probable persistence test; authorization unconfirmed.**

**Observed:** On `vm-windows-dete`, `azureuser` used an SSH-launched command shell to run elevated `reg.exe`, configuring the `LabPersistence` Run value to append `PersistenceExecuted` to `C:\Users\Public\persistence-executed.txt`.

**Inferred:** The lab-labelled value and marker-only command suggest testing rather than a malicious payload. The persistence configuration is real; benign intent is not established.

## 2. Important Timeline Findings
All times UTC, 2026-09-09:
- **18:16:59:** Sysmon recorded inbound SSH from `SOURCE_IP_FROM_INCIDENT` to `DESTINATION_IP_FROM_INCIDENT:22`. Its association with the subsequent user session is plausible, not proven.
- **18:17:04–05:** Security auditing recorded an `azureuser` logon with ID `0x175ebd`; Sysmon linked that session to `sshd.exe → conhost.exe → cmd.exe`.
- **18:19:31:** That command shell launched `reg.exe`; the registry value was successfully set.
- **Through 18:24:31:** Reviewed telemetry did not show the configured marker command executing, marker-file activity, or removal of the value. This does not establish that these activities never occurred.

## 3. Recommended Investigation Steps
- Confirm the test and SSH session with the host owner and `azureuser` operator.
- Review SSH authentication logs to establish the originating client.
- Check the current Run value and marker file; verify any subsequent logon-triggered execution.

## 4. Recommended Response Actions
- Preserve evidence and remove the test value when no longer required.
- If unauthorized, isolate the host, terminate the session, rotate affected credentials, and restrict SSH access.

## 5. Missing or Uncertain Information
Authorization, definitive client-to-session attribution, current registry state, and execution at a later logon remain unknown. Reviewed scope was 18:14:31–18:24:31 UTC.

#### Investigation Performed
* Investigated the activity around the time the registry persistence alert was triggered. I reviewed the relevant Windows and Sysmon logs to check what happened before and after the registry modification.
* The logs showed that `azureuser` opened a command shell through SSH and used `reg.exe` to create the `LabPersistence` value under the Windows Run registry key. The value contained the command `cmd.exe /c echo PersistenceExecuted >> C:\Users\Public\persistence-executed.txt`.
* I also checked the surrounding activity for anything else suspicious, including unexpected processes, other registry changes, suspicious logins, or signs that another user or process was involved. I did not find any other suspicious activity related to the incident.

### Summary:
* Incident Title: Windows Registry Run Key Persistence Detected
* Unique ID: 12
* Severity: Medium
* Mitre Techniques: ["T1547","T1547.001"]
* Status: Closed
* First activity: 2026-09-09 18:19:31+00:00
* Last activity: 2026-09-09 18:19:31+00:00
* Incident ID: 63ce931f-bf9b-44c1-ade7-af1161376153

### Conclusion
The activity was caused by a persistence test that I intentionally performed on the VM to test the Sysmon telemetry and Sentinel detection. The command used was only designed to write `PersistenceExecuted` to a text file if the Run key was executed and did not contain a malicious payload.
The surrounding logs were also reviewed and I did not find any other suspicious activity related to the incident. The incident can therefore be classified as a benign positive, as the detection worked correctly and identified the persistence technique that was intentionally simulated.
