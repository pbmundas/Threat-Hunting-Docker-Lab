Here’s **Hunt 6: Hunting Persistence Techniques (T1543, T1547)** — how attackers stay alive on compromised hosts and how you hunt for those traces in your ELK + ElastAlert lab.

---

# Hunt 6 — Hunting Persistence (T1543: Create or Modify System Process, T1547: Boot or Logon Autostart)

### 1️⃣ Why persistence matters

Attackers persist so they can come back after reboots, credential changes, or defensive actions. Finding persistence early prevents prolonged access and further lateral movement.

Common persistence mechanisms:

* Windows services (new/modified services)
* Scheduled Tasks / Cron jobs
* Registry run keys (`HKLM\...\Run`, `HKCU\...\Run`)
* Startup folder shortcuts / LNK files
* WMI Event subscriptions
* DLL search order hijacks or service image path abuse
* Browser extensions, COM objects, or added ssh keys (cross-platform)

---

### 2️⃣ Hypotheses (example hunting starting points)

* “If a host is compromised, attacker-created services or scheduled tasks will appear on that host.”
* “New `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entries created by non-admin users are suspicious.”
* “Unexpected WMI permanent event subscriptions indicate persistence setup.”

---

### 3️⃣ Relevant log sources & fields

* **Sysmon**

  * Event ID 1 (ProcessCreate): `process_name`, `command_line`
  * Event ID 11 (FileCreate): `file_path`
  * Event ID 7/8 (Registry events) if you enabled Registry auditing: `registry_key`, `registry_value`, `process_name`
  * Event ID 13 (FileDelete) for suspicious removals
* **Windows Security / Task Scheduler**

  * Event ID 4698 (Scheduled Task Created) / 4699 (Deleted) / 4702 (Updated)
  * Event ID 7045 (Service installed) in System log
* **PowerShell / ScriptBlock Logging**

  * Encoded commands that create services, scheduled tasks, or write registry keys
* **Zeek/Suricata / Filebeat**

  * File creations in startup folders, hashes of newly created binaries
* **Inventory/Endpoint management logs** (if available)

  * New/modified service entries, binary hashes, or installed software records

---

### 4️⃣ Useful Kibana queries (start hunting)

Search for service creation (Syslog/System):

```text
event_id: 7045 OR (process_name: "sc.exe" AND command_line: "*create*")
```

Scheduled task creation (security):

```text
event_id: 4698 OR (process_name: "schtasks.exe" AND command_line: "*create*")
```

Registry run keys created/modified (if registry audit logs present):

```text
registry_key: "*\\Run" AND (event_category: "Registry" OR process_name: "reg.exe" OR process_name: "powershell.exe")
```

PowerShell creating persistence:

```text
process_name: "powershell.exe" AND (command_line: "*New-Service*" OR command_line: "*schtasks /create*" OR command_line: "*Set-ItemProperty* -Path *\\Run*")
```

File creation in startup folder:

```text
file_path: "*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" OR file_path: "*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
```

WMI persistence (if WMI logs are collected):

```text
process_name: "wmic.exe" OR command_line: "*__EventFilter* OR *__EventConsumer* OR *__FilterToConsumerBinding*"
```

---

### 5️⃣ Investigation steps & enrichment

1. **Context**: When you see a service/task/registry change — capture `host`, `user`, `timestamp`, `process_name`, `command_line`, and `binary hash` (if available).
2. **Baseline**: Check if the service/task existed previously (compare timestamps and historical indices).
3. **Owner & signing**: Is the binary signed? Owner is `SYSTEM` or regular user? File path in `C:\Windows\System32` vs `C:\Users\<user>\AppData\Roaming`.
4. **Correlate**: Link with prior suspicious activity:

   * Was there PowerShell abuse on that host recently?
   * Any credential dumping or lateral movement events tied to the same host/user?
5. **Static & dynamic analysis**: Pull the binary (if file capture exists) and analyze hash against VirusTotal (outside ELK) — in lab you can store sample hashes and notes.
6. **Triage**: If high-confidence, isolate host or disable service & collect memory image for deeper IR (in a lab, simulate this step).

---

### 6️⃣ Example ElastAlert rule snippets

**Detect new service creation (single high-confidence event):**

```yaml
name: "New Windows Service Creation"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  hours: 1
filter:
- term:
    event_id: 7045
alert:
- "email"
```

**Detect creation of Run key entries by non-standard processes:**

```yaml
name: "Registry Run Key Creation"
type: any
index: "mordor-*"
filter:
- query:
    query_string:
      query: 'registry_key:"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" AND (process_name:"powershell.exe" OR process_name:"reg.exe" OR process_name:"cmd.exe")'
alert:
- "email"
```

**Detect new scheduled tasks:**

```yaml
name: "Scheduled Task Created"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  hours: 1
filter:
- term:
    event_id: 4698
alert:
- "email"
```

Tune filters to your environment to reduce noise (e.g., ignore known admin tools or scheduled backup tasks).

---

### 7️⃣ Dashboard panels to add (triage-focused)

* **Recent Service & Task Changes** panel (list view with host, user, timestamp, command_line)
* **Registry Run Key Changes** (heatmap by host)
* **Startup Folder File Creations** (table with file path and md5/sha256)
* **PowerShell Persistence Attempts** (scriptblock snippets & decoded contents)
* **Host Timeline** — show service/task/registry events + recent process creations and network connections for that host

These help quickly decide whether a persistence artifact is malicious or benign.

---

### 8️⃣ Practical Exercise (hands-on)

1. Run queries above to list recent service creations and scheduled tasks.
2. Pick one suspicious event and collect: `host`, `user`, `timestamp`, `process_name`, `command_line`.
3. Search the host’s timeline (last 24–72 hours) for:

   * PowerShell activity
   * Credential dumping (LSASS access)
   * Outbound network connections (possible C2)
4. If binary hash exists, record it. If not, note file path and creation time.
5. Create/update an ElastAlert rule (use one snippet above) to notify on similar future events.
6. Document your findings in a short hunting note: hypothesis, query used, evidence, confidence, recommended next steps.

---

### Key hunting heuristics (cheat-sheet)

* New service with a user-writable path = suspicious.
* Scheduled task created by `svchost`, `powershell`, or `schtasks` from non-admin accounts = suspicious.
* `HKCU\...\Run` changes by processes that are not part of standard apps = suspicious.
* WMI permanent consumers/filters often indicate stealthy persistence.
* Persistence often follows credential dumping or lateral movement — always correlate.

---
