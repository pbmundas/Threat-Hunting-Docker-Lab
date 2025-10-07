Great — moving on. Here’s **Hunt 8: Hunting Privilege Escalation (T1055, T1548)**. This lesson covers how attackers try to gain higher privileges (SYSTEM / root / admin) and how to detect those actions in your ELK + ElastAlert lab across Windows and Linux hosts.

---

# Hunt 8 — Hunting Privilege Escalation (T1055 Process Injection, T1548 Abuse Elevation Control Mechanism)

### 1️⃣ Why this matters

Privilege escalation is often the bridge from a foothold to full control — once attackers obtain SYSTEM/root, they can disable defenses, dump creds, and move laterally with fewer constraints. Detecting escalation attempts early prevents major damage.

---

### 2️⃣ Common techniques & signs

**Windows**

* Process injection into privileged processes (Event IDs in Sysmon)
* Token stealing / impersonation (seToken operations)
* UAC bypass attempts (fodhelper, eventvwr, sdclt, wusa misuse)
* Abuse of scheduled tasks/services to run elevated code
* DLL search-order hijacks, service image path abuse

**Linux**

* Sudo abuse / crashed or modified sudoers, unexpected `sudo` executions
* Setuid binaries invoked unexpectedly
* `pkexec`, `sudoedit` misuse, or exploitation of SUID-root programs
* Exploitation of kernel/local privilege escalation exploits (unexpected segfaults, core dumps)

---

### 3️⃣ Hypotheses (examples)

* “If an attacker is trying to escalate privileges, they may inject into LSASS or other SYSTEM processes.”
* “If an attacker has local access, they may attempt `sudo` or setuid binary abuse to escalate to root.”
* “Unexpected service binary replacements or service creation with elevated privileges indicate escalation.”

---

### 4️⃣ Relevant log sources & fields

| Platform |                                          Log Source | Useful Fields                                                                           |
| -------- | --------------------------------------------------: | --------------------------------------------------------------------------------------- |
| Windows  | Sysmon (Event IDs 1/3/7/10/8/11/13) & Security logs | `event_id`, `process_name`, `target_process_name`, `command_line`, `user`, `logon_type` |
| Windows  |                    PowerShell / ScriptBlock Logging | `script_block_text`, `command_line`                                                     |
| Linux    |                                     auditd / syslog | `auid`, `exe`, `syscall`, `success`, `acct`, `pid`, `args`                              |
| Linux    |                   Process accounting / process logs | `comm`, `cmdline`, `uid`, `euid`                                                        |
| Both     |                   Endpoint telemetry (if available) | binary hash, parent process tree, file writes                                           |

---

### 5️⃣ Kibana query examples (practical hunts)

**Windows — Process injection attempts (Sysmon Event ID 10 ProcessAccess)**

```text
event_id: 10
AND target_process_name: "lsass.exe"
AND (access_mask: "*Write*" OR access_mask: "*QueryInformation*")
```

**Windows — Known UAC bypass command lines**

```text
process_name.keyword: "fodhelper.exe" OR process_name.keyword: "eventvwr.exe" OR command_line: "*sdclt.exe*"
```

**Windows — Token manipulation / impersonation (Sysmon/ETW if present)**

```text
process_name: "*" AND command_line: "*Impersonate* OR *AdjustTokenPrivileges*"
```

**Linux — Unexpected sudo usage (auditd)**

```text
syscall: "execve" AND exe: "/usr/bin/sudo"
AND NOT (acct: "root" OR acct: "known_admin")
```

**Linux — Setuid binary execution**

```text
syscall: "execve" AND exe.keyword: "/usr/bin/passwd" AND auid: NOT 0
```

**Cross-platform — Service modification creating elevated jobs**

```text
(event_id: 7045) OR (process_name: "systemctl" AND command_line: "*enable*" OR "*start*")
```

---

### 6️⃣ Investigation & enrichment steps

1. **Capture context**: `host`, `user`, `parent process`, `cmdline`, `timestamp`, `binary hash`.
2. **Parent-child chain**: Build a timeline of parent processes — escalation often follows suspicious child processes (e.g., PowerShell → rundll32 → injected process).
3. **Compare baseline**: Is the `sudo` or `fodhelper` call normal for this host/user? Check historical frequency.
4. **Binary integrity**: Check file path and hash; verify code-signing on Windows.
5. **Correlate**: Tie to credential dumping, lateral movement, persistence. Escalation often precedes those.
6. **Memory/forensics**: If high-confidence, capture memory or process dumps for deeper analysis.

---

### 7️⃣ ElastAlert rule examples

**Detect LSASS access (high confidence)**:

```yaml
name: "LSASS Process Access"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  minutes: 15
filter:
- term:
    target_process_name: "lsass.exe"
- query:
    query_string:
      query: "access_mask:*Write* OR access_mask:*QueryInformation*"
alert:
- "email"
```

**Detect unexpected sudo by non-admin users (Linux)**:

```yaml
name: "Unexpected sudo usage"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  hours: 1
filter:
- term:
    exe: "/usr/bin/sudo"
- query:
    query_string:
      query: "auid: NOT 0 AND acct: NOT root"
alert:
- "email"
```

**Detect common UAC-bypass binaries being executed**:

```yaml
name: "UAC Bypass Binary Execution"
type: any
index: "mordor-*"
filter:
- query:
    query_string:
      query: "process_name:(\"fodhelper.exe\" OR \"eventvwr.exe\" OR \"sdclt.exe\")"
alert:
- "email"
```

Tune to environment baseline to avoid noisy admin activities.

---

### 8️⃣ Dashboard panels to add (for escalation triage)

* **Process Injection Attempts** — list `target_process`, `source_process`, `host`, `user`, `cmdline`.
* **Privileged API Calls** — frequency of token APIs or suspicious system calls.
* **Sudo & Setuid Executions** — top users invoking sudo or SUID binaries, with anomalies highlighted.
* **UAC Bypass Executions** — quick table for known bypass binaries & their parents.
* **Host Timeline View** — escalate indicator combining service changes, LSASS access, and sudo events.

---

### 9️⃣ Practical exercise (hands-on)

1. Run the **LSASS ProcessAccess** query to find any `lsass.exe` access in the lab.
2. For each hit, gather: `host`, `user`, `parent_process`, `command_line`, `timestamp`, `binary_hash`.
3. Check the host timeline (previous 24–72 hours) for:

   * PowerShell abuse
   * Credential dumping events
   * Service/task creations
   * Outbound C2 connections
4. Run `sudo`/`setuid` queries on Linux hosts to find unexpected executions by non-admins.
5. Create or tune ElastAlert rules from the snippets above to alert on high-confidence events.
6. Document one full escalation investigation: hypothesis → query → findings → confidence → recommended containment.

---

### Heuristics cheat-sheet (quick wins)

* Any process writing to or opening LSASS memory = **high priority**.
* Unexpected `sudo` by low-privileged accounts = **investigate immediately**.
* Execution of known UAC-bypass binaries triggered by non-admin processes = **higher suspicion**.
* Privilege escalation attempts often occur shortly after credential dumping or after suspicious network connections — **always correlate**.

---

