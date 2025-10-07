
* **Hypothesis**: Why this query is relevant (based on Mordor TTPs/MITRE ATT&CK).
* **Query (KQL/ES)**: Ready to paste in Kibana Discover or use in saved searches.

I have structured them by **threat category** for clarity. 

---

### **Execution / Command & Scripting Interpreter (T1059)**

1. **Hypothesis:** Suspicious PowerShell execution with encoded command may indicate malware execution.
   **Query:**

   ```kql
   process_name: "powershell.exe" AND process_command_line: ("-EncodedCommand" OR "-enc" OR "IEX" OR "Invoke-Expression")
   ```

2. **Hypothesis:** PowerShell executed from temporary folders often indicates fileless malware.
   **Query:**

   ```kql
   process_name: "powershell.exe" AND process_path: ("C:\\Users\\*\\AppData\\Local\\Temp\\*" OR "C:\\Windows\\Temp\\*")
   ```

3. **Hypothesis:** WMI execution used by attackers for lateral movement.
   **Query:**

   ```kql
   process_name: "wmic.exe" AND process_command_line: "*process call create*"
   ```

4. **Hypothesis:** Cmd.exe executing encoded scripts or network tools indicates malicious automation.
   **Query:**

   ```kql
   process_name: "cmd.exe" AND process_command_line: ("*base64*" OR "*powershell*")
   ```

5. **Hypothesis:** MSHTA executing remote scripts may indicate fileless malware.
   **Query:**

   ```kql
   process_name: "mshta.exe" AND process_command_line: ("http*" OR "https*")
   ```

6. **Hypothesis:** CScript/WScript executing suspicious scripts may indicate automation malware.
   **Query:**

   ```kql
   process_name: ("cscript.exe" OR "wscript.exe") AND process_command_line: ("*.vbs" OR "*.js")
   ```

7. **Hypothesis:** Unusual execution of admin tools from user directories may indicate misuse.
   **Query:**

   ```kql
   process_path: "C:\\Users\\*" AND process_name: ("taskkill.exe" OR "net.exe" OR "sc.exe")
   ```

8. **Hypothesis:** PowerShell downloading files from the internet could indicate C2 or dropper activity.
   **Query:**

   ```kql
   process_name: "powershell.exe" AND process_command_line: ("Invoke-WebRequest" OR "DownloadFile" OR "New-Object System.Net.WebClient")
   ```

9. **Hypothesis:** Rundll32 executing remote scripts is suspicious and often used in fileless attacks.
   **Query:**

   ```kql
   process_name: "rundll32.exe" AND process_command_line: ("http*" OR "https*" OR "*.dll")
   ```

10. **Hypothesis:** Executables running from unusual directories (Temp, Downloads) may indicate malware.
    **Query:**

    ```kql
    process_path: ("C:\\Users\\*\\Downloads\\*" OR "C:\\Users\\*\\AppData\\Local\\Temp\\*") AND process_name: "*.*"
    ```

---

### **Persistence (T1543, T1053, Run Keys)**

11. **Hypothesis:** Creation of new Windows service may indicate persistence.
    **Query:**

    ```kql
    event_id: 7045
    ```

12. **Hypothesis:** Scheduled tasks created by unusual users may indicate persistence.
    **Query:**

    ```kql
    event_id: 4698 AND user_name: NOT ("SYSTEM" OR "Administrator")
    ```

13. **Hypothesis:** Registry Run keys modified may indicate persistence.
    **Query:**

    ```kql
    registry_key_path: ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" OR "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    ```

14. **Hypothesis:** New startup files in user directories indicate potential persistence.
    **Query:**

    ```kql
    file_path: ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" OR "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
    ```

15. **Hypothesis:** Auto-start entries created in unusual registry locations.
    **Query:**

    ```kql
    registry_key_path: ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" OR "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    ```

16. **Hypothesis:** Task Scheduler jobs running scripts from temp directories are suspicious.
    **Query:**

    ```kql
    event_id: 4698 AND task_path: ("*\\Temp\\*" OR "*\\AppData\\Local\\Temp\\*")
    ```

17. **Hypothesis:** Services installed with unusual binary path indicate malicious persistence.
    **Query:**

    ```kql
    event_id: 7045 AND binary_path: ("C:\\Users\\*" OR "C:\\Temp\\*")
    ```

18. **Hypothesis:** Registry modifications for WMI Event Subscriptions may indicate stealth persistence.
    **Query:**

    ```kql
    registry_key_path: "HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\*EventFilter*"
    ```

19. **Hypothesis:** Scheduled tasks triggered by unusual users or at odd times.
    **Query:**

    ```kql
    event_id: 4698 AND (task_trigger_type: "*" OR user_name: NOT ("SYSTEM" OR "Administrator"))
    ```

20. **Hypothesis:** Malicious scripts placed in startup folder executed by users.
    **Query:**

    ```kql
    file_path: "*\\Startup\\*" AND process_name: ("*.vbs" OR "*.bat" OR "*.ps1")
    ```

Great — continuing with the next **20 hunting queries (21–40)**. Each entry includes a short **hypothesis** and a **KQL** query you can paste directly into **Kibana Discover** (adjust field names if your ingested schema uses slightly different names; I used common Sysmon/Winlogbeat/Elasticsearch field names like `process_name`, `process_command_line`, `event_id`, `dest_ip`, `user_name`, `file_path`, `registry_key_path`, `target_process_name`, `bytes_sent`, etc.).

---

### **Credential Access / Dumping (T1003)**

21. **Hypothesis:** Mimikatz or known credential dumping binaries executed on hosts.
    **Query:**

    ```kql
    process_name: "mimikatz.exe" OR process_command_line: "*sekurlsa*"
    ```

22. **Hypothesis:** Processes accessing LSASS memory (Sysmon ProcessAccess events).
    **Query:**

    ```kql
    event_id: 10 AND target_process_name: "lsass.exe"
    ```

23. **Hypothesis:** Suspicious rundll32/certutil operations used to stage credential dumper.
    **Query:**

    ```kql
    process_name: ("rundll32.exe" OR "certutil.exe") AND process_command_line: ("-decode" OR "http" OR "https")
    ```

24. **Hypothesis:** PowerShell invoking credential-dumping modules or commands.
    **Query:**

    ```kql
    process_name: "powershell.exe" AND process_command_line: ("Invoke-Mimikatz" OR "sekurlsa" OR "LogonPasswords")
    ```

25. **Hypothesis:** Attempts to read SAM / SYSTEM registry hives (backup or file access).
    **Query:**

    ```kql
    process_command_line: ("\\Windows\\System32\\config\\SAM" OR "\\Windows\\System32\\config\\SYSTEM") OR file_path: "*\\config\\SAM"
    ```

---

### **Command & Control / Network (T1071)**

26. **Hypothesis:** External connections to rare destination ports (non-80/443/53) may indicate C2.
    **Query:**

    ```kql
    event_type: "network_connection" AND dest_port: NOT (80 OR 443 OR 53 OR 22 OR 21)
    ```

27. **Hypothesis:** Hosts with repeated outbound connections to same external IP (beaconing).
    **Query:**

    ```kql
    event_type: "network_connection" AND NOT dest_ip: ("10.*" OR "192.168.*" OR "172.16.*" OR "172.31.*") | stats count() by host.name, dest_ip | where count > 10
    ```

    *(Paste the filter part in Discover; use Lens/TSVB/TS query for aggregation.)*

28. **Hypothesis:** PowerShell spawning network connections (likely download/exfil).
    **Query:**

    ```kql
    process_name: "powershell.exe" AND event_type: "network_connection"
    ```

29. **Hypothesis:** DNS queries with long or random subdomains often used by DNS-based C2.
    **Query:**

    ```kql
    event_type: "dns" AND query: /[a-z0-9]{8,}\./
    ```

30. **Hypothesis:** Large outbound data transfers to external IPs indicate exfiltration.
    **Query:**

    ```kql
    event_type: "network_connection" AND bytes_sent: >= 5000000 AND NOT dest_ip: ("10.*" OR "192.168.*" OR "172.16.*")
    ```

---

### **Lateral Movement / Remote Execution (T1021)**

31. **Hypothesis:** PsExec usage to run commands on remote hosts.
    **Query:**

    ```kql
    process_name: "psexec.exe" OR process_command_line: "*\\\\*"
    ```

32. **Hypothesis:** RDP connections initiated from non-admin workstations.
    **Query:**

    ```kql
    event_id: 4624 AND logon_type: 10 AND NOT source_ip: ("10.*" OR "192.168.*")
    ```

33. **Hypothesis:** WMI or WinRM remote executions from user endpoints.
    **Query:**

    ```kql
    process_name: ("wmic.exe" OR "winrm.exe" OR "powershell.exe") AND process_command_line: "*-ComputerName*"
    ```

34. **Hypothesis:** SMB connections to multiple hosts from single host indicates lateral scanning/propagation.
    **Query:**

    ```kql
    event_type: "network_connection" AND dest_port: 445 AND source_ip: * | stats distinct_count(dest_ip) by host.name | where distinct_count > 5
    ```

    *(Use aggregation visual or Dev Tools for counts.)*

35. **Hypothesis:** New administrative logons on many hosts by same account (credential reuse).
    **Query:**

    ```kql
    event_id: 4624 AND logon_type: (3 OR 10) AND user_name: * | stats distinct_count(host.name) by user_name | where distinct_count > 5
    ```

---

### **Persistence & File Activity (T1543 / T1053 / T1074)**

36. **Hypothesis:** New service installed by non-standard binary path or non-admin user.
    **Query:**

    ```kql
    event_id: 7045 AND binary_path: ("C:\\Users\\*" OR "C:\\Temp\\*") AND user_name: NOT ("SYSTEM" OR "Administrator")
    ```

37. **Hypothesis:** Scheduled task created to run PowerShell or scripts from temp.
    **Query:**

    ```kql
    event_id: 4698 AND process_command_line: ("*powershell*" OR "*\\Temp\\*")
    ```

38. **Hypothesis:** File writes to archives or compressible folder indicating staging for exfil.
    **Query:**

    ```kql
    event_id: 11 AND file_path: ("*\\Downloads\\*" OR "*\\Temp\\*") AND file_name: ("*.zip" OR "*.rar" OR "*.7z")
    ```

39. **Hypothesis:** Creation of new scheduled tasks with suspicious names or paths.
    **Query:**

    ```kql
    event_id: 4698 AND task_name: ("*Updater*" OR "*Windows Update*" OR "*svchost*") AND task_path: NOT ("\\Microsoft\\")
    ```

40. **Hypothesis:** Service image path changed (possible binary replacement).
    **Query:**

    ```kql
    event_id: 7045 AND change_type: "modify" AND binary_path: NOT ("C:\\Windows\\System32\\*")
    ```


### **Credential Access / Dumping (T1003)**

21. **Hypothesis:** Mimikatz or known credential dumping binaries executed on hosts.
    **Query:**

    ```kql
    process_name: "mimikatz.exe" OR process_command_line: "*sekurlsa*"
    ```

22. **Hypothesis:** Processes accessing LSASS memory (Sysmon ProcessAccess events).
    **Query:**

    ```kql
    event_id: 10 AND target_process_name: "lsass.exe"
    ```

23. **Hypothesis:** Suspicious rundll32/certutil operations used to stage credential dumper.
    **Query:**

    ```kql
    process_name: ("rundll32.exe" OR "certutil.exe") AND process_command_line: ("-decode" OR "http" OR "https")
    ```

24. **Hypothesis:** PowerShell invoking credential-dumping modules or commands.
    **Query:**

    ```kql
    process_name: "powershell.exe" AND process_command_line: ("Invoke-Mimikatz" OR "sekurlsa" OR "LogonPasswords")
    ```

25. **Hypothesis:** Attempts to read SAM / SYSTEM registry hives (backup or file access).
    **Query:**

    ```kql
    process_command_line: ("\\Windows\\System32\\config\\SAM" OR "\\Windows\\System32\\config\\SYSTEM") OR file_path: "*\\config\\SAM"
    ```

---

### **Command & Control / Network (T1071)**

26. **Hypothesis:** External connections to rare destination ports (non-80/443/53) may indicate C2.
    **Query:**

    ```kql
    event_type: "network_connection" AND dest_port: NOT (80 OR 443 OR 53 OR 22 OR 21)
    ```

27. **Hypothesis:** Hosts with repeated outbound connections to same external IP (beaconing).
    **Query:**

    ```kql
    event_type: "network_connection" AND NOT dest_ip: ("10.*" OR "192.168.*" OR "172.16.*" OR "172.31.*") | stats count() by host.name, dest_ip | where count > 10
    ```

    *(Paste the filter part in Discover; use Lens/TSVB/TS query for aggregation.)*

28. **Hypothesis:** PowerShell spawning network connections (likely download/exfil).
    **Query:**

    ```kql
    process_name: "powershell.exe" AND event_type: "network_connection"
    ```

29. **Hypothesis:** DNS queries with long or random subdomains often used by DNS-based C2.
    **Query:**

    ```kql
    event_type: "dns" AND query: /[a-z0-9]{8,}\./
    ```

30. **Hypothesis:** Large outbound data transfers to external IPs indicate exfiltration.
    **Query:**

    ```kql
    event_type: "network_connection" AND bytes_sent: >= 5000000 AND NOT dest_ip: ("10.*" OR "192.168.*" OR "172.16.*")
    ```


### **Lateral Movement / Remote Execution (T1021)**

31. **Hypothesis:** PsExec usage to run commands on remote hosts.
    **Query:**

    ```kql
    process_name: "psexec.exe" OR process_command_line: "*\\\\*"
    ```

32. **Hypothesis:** RDP connections initiated from non-admin workstations.
    **Query:**

    ```kql
    event_id: 4624 AND logon_type: 10 AND NOT source_ip: ("10.*" OR "192.168.*")
    ```

33. **Hypothesis:** WMI or WinRM remote executions from user endpoints.
    **Query:**

    ```kql
    process_name: ("wmic.exe" OR "winrm.exe" OR "powershell.exe") AND process_command_line: "*-ComputerName*"
    ```

34. **Hypothesis:** SMB connections to multiple hosts from single host indicates lateral scanning/propagation.
    **Query:**

    ```kql
    event_type: "network_connection" AND dest_port: 445 AND source_ip: * | stats distinct_count(dest_ip) by host.name | where distinct_count > 5
    ```

    *(Use aggregation visual or Dev Tools for counts.)*

35. **Hypothesis:** New administrative logons on many hosts by same account (credential reuse).
    **Query:**

    ```kql
    event_id: 4624 AND logon_type: (3 OR 10) AND user_name: * | stats distinct_count(host.name) by user_name | where distinct_count > 5
    ```

---

### **Persistence & File Activity (T1543 / T1053 / T1074)**

36. **Hypothesis:** New service installed by non-standard binary path or non-admin user.
    **Query:**

    ```kql
    event_id: 7045 AND binary_path: ("C:\\Users\\*" OR "C:\\Temp\\*") AND user_name: NOT ("SYSTEM" OR "Administrator")
    ```

37. **Hypothesis:** Scheduled task created to run PowerShell or scripts from temp.
    **Query:**

    ```kql
    event_id: 4698 AND process_command_line: ("*powershell*" OR "*\\Temp\\*")
    ```

38. **Hypothesis:** File writes to archives or compressible folder indicating staging for exfil.
    **Query:**

    ```kql
    event_id: 11 AND file_path: ("*\\Downloads\\*" OR "*\\Temp\\*") AND file_name: ("*.zip" OR "*.rar" OR "*.7z")
    ```

39. **Hypothesis:** Creation of new scheduled tasks with suspicious names or paths.
    **Query:**

    ```kql
    event_id: 4698 AND task_name: ("*Updater*" OR "*Windows Update*" OR "*svchost*") AND task_path: NOT ("\\Microsoft\\")
    ```

40. **Hypothesis:** Service image path changed (possible binary replacement).
    **Query:**

    ```kql
    event_id: 7045 AND change_type: "modify" AND binary_path: NOT ("C:\\Windows\\System32\\*")
    ```


### **Defense Evasion / LOLBins (T1218 / T1140)**

41. **Hypothesis:** Certutil.exe downloading or decoding files is often used for malware staging.

```kql
process_name: "certutil.exe" AND process_command_line: ("-decode" OR "-urlcache" OR "-f" OR "http*")
```

42. **Hypothesis:** Bitsadmin used for downloading remote files suspiciously.

```kql
process_name: "bitsadmin.exe" AND process_command_line: ("*http*" OR "*https*")
```

43. **Hypothesis:** MSHTA executing remote scripts for fileless attacks.

```kql
process_name: "mshta.exe" AND process_command_line: ("http*" OR "https*")
```

44. **Hypothesis:** Regsvr32 executing scripts from unusual paths.

```kql
process_name: "regsvr32.exe" AND process_command_line: ("*.sct" OR "*.dll")
```

45. **Hypothesis:** Rundll32 executing scripts not in System32 folder.

```kql
process_name: "rundll32.exe" AND process_path: NOT "C:\\Windows\\System32\\*"
```

46. **Hypothesis:** WMI subscription creation indicates stealthy persistence.

```kql
registry_key_path: "HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\*EventFilter*"
```

47. **Hypothesis:** Debuggers or security tools disabled or tampered.

```kql
process_command_line: ("sc stop winmgmt" OR "sc delete" OR "taskkill /f /im")
```

48. **Hypothesis:** PowerShell scripts hiding in AppData or Temp folders.

```kql
process_name: "powershell.exe" AND process_path: ("C:\\Users\\*\\AppData\\Local\\Temp\\*" OR "C:\\Users\\*\\AppData\\Roaming\\*")
```

49. **Hypothesis:** Obfuscated scripts executed by LOLBins.

```kql
process_command_line: ("-enc" OR "-EncodedCommand" OR "IEX")
```

50. **Hypothesis:** Fileless malware loaded via legitimate admin tools.

```kql
process_name: ("rundll32.exe" OR "regsvr32.exe" OR "mshta.exe") AND process_command_line: ("http*" OR "*.dll" OR "*.sct")
```


### **Process Injection / Manipulation (T1055)**

51. **Hypothesis:** Suspicious process accessing lsass.exe or other processes for token theft.

```kql
event_id: 10 AND target_process_name: "lsass.exe"
```

52. **Hypothesis:** Rundll32 loading unsigned DLLs into other processes.

```kql
process_name: "rundll32.exe" AND process_command_line: "*\\Temp\\*"
```

53. **Hypothesis:** Powershell spawning other processes in memory (no disk artifact).

```kql
process_name: "powershell.exe" AND process_command_line: ("Start-Process" AND "-WindowStyle Hidden")
```

54. **Hypothesis:** CScript/WScript executing scripts in user temp folders.

```kql
process_name: ("cscript.exe" OR "wscript.exe") AND process_path: ("C:\\Users\\*\\AppData\\Local\\Temp\\*")
```

55. **Hypothesis:** MSHTA loading encoded scripts from memory.

```kql
process_name: "mshta.exe" AND process_command_line: "-enc"
```

---

### **Registry / WMI / Other Persistence (T1547 / T1546)**

56. **Hypothesis:** Run key modified with suspicious binary path.

```kql
registry_key_path: ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*") AND process_path: NOT "C:\\Windows\\System32\\*"
```

57. **Hypothesis:** RunOnce key modified unexpectedly.

```kql
registry_key_path: ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*" OR "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*") AND process_path: NOT "C:\\Windows\\System32\\*"
```

58. **Hypothesis:** Scheduled tasks calling scripts from temp directories.

```kql
event_id: 4698 AND task_path: "*\\Temp\\*"
```

59. **Hypothesis:** WMI Event Filter / Consumer / Binding created.

```kql
registry_key_path: "HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\*Event*"
```

60. **Hypothesis:** Service image path changed to non-standard binary location.

```kql
event_id: 7045 AND binary_path: NOT "C:\\Windows\\System32\\*"
```


### **Command & Control / Network Anomalies (T1071, T1043)**

61. **Hypothesis:** Outbound connections to rare or suspicious IPs indicate possible C2.

```kql
event_type: "network_connection" AND NOT dest_ip: ("10.*" OR "192.168.*" OR "172.16.*" OR "172.31.*")
```

62. **Hypothesis:** Hosts making repeated outbound connections to same IP suggest beaconing.

```kql
event_type: "network_connection" | stats count() by host.name, dest_ip | where count > 10
```

63. **Hypothesis:** High volume of DNS requests to rare domains may indicate DNS C2.

```kql
event_type: "dns" AND NOT query: ("*.local" OR "*.lan" OR "*.internal")
```

64. **Hypothesis:** PowerShell initiating network connections externally.

```kql
process_name: "powershell.exe" AND event_type: "network_connection" AND NOT dest_ip: ("10.*" OR "192.168.*")
```

65. **Hypothesis:** Large outbound data transfers suggest exfiltration.

```kql
event_type: "network_connection" AND bytes_sent: >= 5000000 AND NOT dest_ip: ("10.*" OR "192.168.*")
```

66. **Hypothesis:** Suspicious FTP or SMB traffic from endpoints.

```kql
event_type: "network_connection" AND dest_port: (21 OR 445 OR 139)
```

67. **Hypothesis:** Unexpected ICMP traffic from workstations could be command signaling.

```kql
event_type: "network_connection" AND protocol: "ICMP"
```

68. **Hypothesis:** C2 using uncommon ports for HTTPS (other than 443).

```kql
event_type: "network_connection" AND dest_port: NOT (80 OR 443) AND process_name: "powershell.exe"
```

69. **Hypothesis:** Hosts connecting to many different external IPs over short period.

```kql
event_type: "network_connection" | stats distinct_count(dest_ip) by host.name | where distinct_count > 5
```

70. **Hypothesis:** DNS queries with high entropy (random subdomains).

```kql
event_type: "dns" AND query: /[a-z0-9]{8,}\./
```


### **Lateral Movement / Recon (T1021, T1082, T1046)**

71. **Hypothesis:** PsExec used to execute commands remotely.

```kql
process_name: "psexec.exe" OR process_command_line: "*\\\\*"
```

72. **Hypothesis:** RDP connections initiated by non-admin hosts.

```kql
event_id: 4624 AND logon_type: 10 AND NOT source_ip: ("10.*" OR "192.168.*")
```

73. **Hypothesis:** WMI or WinRM remote execution commands.

```kql
process_name: ("wmic.exe" OR "winrm.exe" OR "powershell.exe") AND process_command_line: "*-ComputerName*"
```

74. **Hypothesis:** SMB enumeration on multiple hosts by same user.

```kql
event_type: "network_connection" AND dest_port: 445 | stats distinct_count(dest_ip) by user_name | where distinct_count > 5
```

75. **Hypothesis:** New administrative logons on multiple hosts by one account.

```kql
event_id: 4624 AND logon_type: (3 OR 10) | stats distinct_count(host.name) by user_name | where distinct_count > 5
```

76. **Hypothesis:** Network scanning behavior from endpoint.

```kql
event_type: "network_connection" | stats distinct_count(dest_port) by source_ip | where distinct_count > 50
```

77. **Hypothesis:** Recon using netstat/arp commands.

```kql
process_name: ("netstat.exe" OR "arp.exe") AND process_command_line: "*"
```

78. **Hypothesis:** Attempts to enumerate shares on remote hosts.

```kql
process_name: "net.exe" AND process_command_line: "view \\\\*"
```

79. **Hypothesis:** Suspicious ping sweeps or ICMP requests to multiple hosts.

```kql
event_type: "network_connection" AND protocol: "ICMP" | stats distinct_count(dest_ip) by host.name | where distinct_count > 10
```

80. **Hypothesis:** Lateral movement using RDP, SMB, or RPC outside business hours.

```kql
event_id: 4624 AND logon_type: (3 OR 10) AND @timestamp: ("now-7d/d" TO "now") AND hour_of_day: >= 20 OR hour_of_day: <= 6
```


### **Privilege Escalation / System (T1068 / T1548)**

81. **Hypothesis:** Unusual sudo or administrative command executed on endpoints.

```kql
process_name: "sudo" OR process_command_line: "* -i" OR user_name: NOT "root"
```

82. **Hypothesis:** Exploitation of system binaries for privilege escalation.

```kql
process_name: ("runas.exe" OR "cmstp.exe") AND process_command_line: "*"
```

83. **Hypothesis:** Setuid/setgid file modifications on Linux endpoints.

```kql
file_permission: ("suid" OR "sgid") AND file_path: "/usr/*"
```

84. **Hypothesis:** UAC bypass attempts using system tools.

```kql
process_name: ("eventvwr.exe" OR "fodhelper.exe") AND process_command_line: "*"
```

85. **Hypothesis:** Processes spawning with SYSTEM privileges from user sessions.

```kql
process_name: "*.*" AND user_name: "SYSTEM" AND parent_user_name: NOT "SYSTEM"
```


### **Malware Staging / File Activity (T1074 / T1036)**

86. **Hypothesis:** Executables dropped in Temp folders by non-admin users.

```kql
process_name: "*.*" AND file_path: ("C:\\Users\\*\\AppData\\Local\\Temp\\*" OR "C:\\Temp\\*")
```

87. **Hypothesis:** Suspicious archive or installer files created outside program directories.

```kql
file_name: ("*.exe" OR "*.msi" OR "*.zip" OR "*.rar") AND file_path: NOT ("C:\\Program Files\\*" OR "C:\\Windows\\*")
```

88. **Hypothesis:** Script files written to startup directories.

```kql
file_path: ("*\\Startup\\*") AND file_name: ("*.bat" OR "*.vbs" OR "*.ps1")
```

89. **Hypothesis:** Shadow copies or backup files created in unusual locations.

```kql
file_path: ("*.vhd" OR "*.bak") AND NOT file_path: ("C:\\Windows\\*" OR "C:\\Program Files\\*")
```

90. **Hypothesis:** Executables mimicking system binaries (e.g., svchost.exe not in System32).

```kql
process_name: "svchost.exe" AND process_path: NOT "C:\\Windows\\System32\\*"
```


### **Registry / Configuration / WMI (T1547 / T1546)**

91. **Hypothesis:** Registry keys created/modified with suspicious values.

```kql
registry_key_path: "*" AND process_name: ("reg.exe" OR "powershell.exe") AND NOT registry_key_path: ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*")
```

92. **Hypothesis:** Auto-run scripts written to unusual locations.

```kql
file_path: ("C:\\Users\\*\\AppData\\Roaming\\*" OR "C:\\Users\\*\\AppData\\Local\\*") AND file_name: ("*.vbs" OR "*.ps1" OR "*.bat")
```

93. **Hypothesis:** WMI filters or event consumers created/modified.

```kql
registry_key_path: "HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\*Event*"
```

94. **Hypothesis:** Scheduled tasks modified with unusual binaries.

```kql
event_id: 4698 AND task_path: NOT "\\Microsoft\\*" AND process_command_line: NOT "*\\System32\\*"
```

95. **Hypothesis:** Changes to startup folders by non-standard binaries.

```kql
file_path: ("*\\Startup\\*") AND process_name: NOT ("explorer.exe" OR "cmd.exe" OR "powershell.exe")
```

---

### **Cross-correlation / Combined Anomalies**

96. **Hypothesis:** PowerShell executed from Temp folder + network connections to external IP.

```kql
process_name: "powershell.exe" AND process_path: ("C:\\Users\\*\\AppData\\Local\\Temp\\*") AND event_type: "network_connection"
```

97. **Hypothesis:** Credential dumping binary executed + new service installed.

```kql
(process_name: "mimikatz.exe" OR process_command_line: "*sekurlsa*") AND event_id: 7045
```

98. **Hypothesis:** Fileless malware executed via MSHTA + network beaconing.

```kql
process_name: "mshta.exe" AND process_command_line: "*http*" AND event_type: "network_connection"
```

99. **Hypothesis:** Scheduled tasks created + outbound network traffic outside office hours.

```kql
event_id: 4698 AND @timestamp: ("now-7d/d" TO "now") AND hour_of_day: >= 20 OR hour_of_day: <= 6 AND event_type: "network_connection"
```

100. **Hypothesis:** PowerShell with encoded command + writes to startup folder.

```kql
process_name: "powershell.exe" AND process_command_line: ("-enc" OR "-EncodedCommand") AND file_path: "*\\Startup\\*"
```








