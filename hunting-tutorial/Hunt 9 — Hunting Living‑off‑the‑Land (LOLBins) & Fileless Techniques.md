Excellent — Hunt 9 it is. We’ll cover **Living-off-the-Land (LoL) & Fileless Techniques** — how attackers abuse legitimate OS tools (LOLBins / trusted utilities) and in-memory-only techniques to avoid dropping binaries. This is a high-opportunity area for hunting because defenders often ignore “normal” tools.

---

# Hunt 9 — Hunting Living‑off‑the‑Land (LOLBins) & Fileless Techniques

### Goal

Detect abuse of legitimate system tools and purely in-memory attacks by combining process telemetry, command-line analysis, parent→child relationships, scriptblock/command logging, registry/WMI changes, and network behavior.

---

## 1) Why LoLBins & fileless matter

* Attackers use built-in utilities (PowerShell, regsvr32, rundll32, mshta, certutil, wmic, bitsadmin, cscript, wscript, netsh, sc, schtasks) to blend in.
* Fileless attacks execute in memory or via trusted processes (reduces disk artifacts).
* Detection requires **profiling normal behavior** and looking for anomalous deviations.

---

## 2) Common LOLBins & fileless patterns (Windows & Linux)

**Windows common LOLBins**

* `powershell.exe` — encoded commands, Invoke-Expression, scriptblock obfuscation.
* `rundll32.exe` / `regsvr32.exe` / `mshta.exe` — remote script loading or COM abuse.
* `certutil.exe` — file download / base64 decode.
* `bitsadmin.exe` / `bits` APIs — stealthy downloads.
* `cscript.exe` / `wscript.exe` — VBScript/JS execution.
* `wmic.exe`, `psexec.exe`, `schtasks.exe` — remote execution / persistence helpers.
* `taskhost.exe` / `svchost.exe` — suspicious parent process usage.

**Linux equivalents**

* `python -c`, `perl -e`, `ruby -e`, `bash -c` — inline scripts.
* `curl|wget|nc` used for staged payloads in memory.
* `ld.so` / suspicious `LD_PRELOAD` usage for injection.
* `systemd-run` or `cron` abuse for in-memory payloads.

---

## 3) Hypotheses (hunt starters)

* “If an attacker is active, they may use `regsvr32`/`rundll32`/`mshta` to execute remote or encoded scripts.”
* “If PowerShell is used with encoded commands or ‘-nop -w hidden -EncodedCommand’, it’s likely malicious.”
* “Legitimate utilities invoked by uncommon parent processes, or at strange hours, indicate abuse.”
* “Base64-decoding activities by certutil or PowerShell that result in new network connections indicate staging.”

---

## 4) Logs & fields to collect

* **Sysmon**: Event IDs 1 (Process Create), 3 (Network Connect), 10 (ProcessAccess), 11 (FileCreate), 7/8 (Registry) — include `process_name`, `parent_process_name`, `command_line`, `user`, `hash`, `process_guid`.
* **PowerShell**: ScriptBlockLogging, ModuleLogging, Transcription — `script_block_text`, decoded content.
* **Windows Security**: 4688 (process creation) with `NewProcessName`, `CommandLine`.
* **Auditd / syslog (Linux)**: `execve` events, `cmdline`, `uid`, `euid`.
* **Network logs**: destination IP/domain, ports, bytes, frequency (beaconing).
* **Filebeat / File monitoring**: file writes to `%TEMP%`, `AppData\Roaming`, unexpected DLL loads.

---

## 5) Kibana query examples (practical hunts)

### A. PowerShell encoded / suspicious command-lines

```text
process_name: "powershell.exe"
AND (command_line: "*-EncodedCommand*" OR command_line: "*-enc*" OR command_line: "*-nop*" OR command_line: "*IEX*" OR command_line: "*Invoke-Expression*")
```

### B. Certutil used to download or decode

```text
process_name: "certutil.exe"
AND (command_line: "*-urlcache*" OR command_line: "*-decode*")
```

### C. Regsvr32 / Rundll32 / Mshta remote script invocation

```text
process_name: "regsvr32.exe" OR process_name: "rundll32.exe" OR process_name: "mshta.exe"
AND (command_line: "*http:*" OR command_line: "*https:*" OR command_line: "*-s*")
```

### D. Parent-child anomaly (trusted tool launched by unusual parent)

```text
process_name: "rundll32.exe"
AND parent_process_name: NOT ("explorer.exe" OR "services.exe" OR "svchost.exe")
```

### E. In-memory / inline Linux execution

```text
exe: "/usr/bin/python"
AND cmdline: "*-c*" OR cmdline: "*-m*"
```

### F. Base64 or long one-liner detection

```text
command_line: /[A-Za-z0-9+\/]{100,}/
```

(Detects long base64 strings; tune length to reduce noise.)

---

## 6) ElastAlert example rules

### Rule: PowerShell Encoded Command

```yaml
name: "PowerShell Encoded Command"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  minutes: 5
filter:
- term:
    process_name: "powershell.exe"
- query:
    query_string:
      query: "command_line: *-EncodedCommand* OR command_line: *-enc* OR command_line: *IEX* OR command_line: *Invoke-Expression*"
alert:
- "email"
```

### Rule: Trusted Utility Download (certutil/regsvr32/mshta)

```yaml
name: "Trusted Utility Remote Download"
type: any
index: "mordor-*"
filter:
- query:
    query_string:
      query: "process_name:(\"certutil.exe\" OR \"regsvr32.exe\" OR \"mshta.exe\" OR \"rundll32.exe\") AND command_line:(\"http:\" OR \"https:\")"
alert:
- "email"
```

### Rule: Parent-Child Anomaly for LOLBin usage

```yaml
name: "LOLBin Launched by Unusual Parent"
type: any
index: "mordor-*"
filter:
- query:
    query_string:
      query: "process_name:(\"rundll32.exe\" OR \"regsvr32.exe\" OR \"mshta.exe\" OR \"certutil.exe\") AND NOT parent_process_name:(\"explorer.exe\" OR \"services.exe\" OR \"svchost.exe\" OR \"taskhost.exe\")"
alert:
- "email"
```

---

## 7) Investigation steps & enrichment

1. **Capture the artifact**: `process_name`, `parent_process_name`, `command_line`, `user`, `host`, `timestamp`, `process_guid`.
2. **Decode & inspect**: If PowerShell encoded or base64, decode scriptblock — look for `IEX`, `Invoke-WebRequest`, download-and-execute patterns.
3. **Parent process chain**: Build parent→child tree. Unusual parents (e.g., Word → rundll32) are suspicious.
4. **Network correlation**: If the process opened outbound connections, lookup domain/IP reputation and frequency (beaconing).
5. **Check persistence**: Did the one-liner create service, scheduled task, or registry entry? Search for file writes to startup folders or `HKCU\...\Run`.
6. **File/Hash**: If a file was created, capture hash and scan (in lab, keep a catalog of known benign admin utilities).
7. **Context**: Was the activity during maintenance window or from an IT admin? Cross-check with ticketing or admin lists.
8. **Contain & remediate**: If confirmed malicious, isolate host, dump memory, collect artifacts, and remove persistence.

---

## 8) Dashboard panels to add (triage & hunting)

* **LOLBin Activity Feed** — timeseries and table for any executions of known LOLBins with `command_line` visible.
* **PowerShell ScriptBlock Viewer** — panel showing decoded scriptblocks and top offending hosts.
* **Parent→Child Tree** — quick lookup to show unusual parents for known utilities.
* **Base64/Long One-liners** — heatmap showing frequency by host and hour.
* **Certutil / mshta / regsvr32 Downloads** — list with destination domains/IPs and bytes transferred.
* **Linux Inline Execution** — top `python -c` / `bash -c` invocations with user context.

---

## 9) Heuristics / quick wins (cheat sheet)

* Long command lines with base64-looking strings → **high suspicion**.
* `rundll32` / `regsvr32` / `mshta` connecting to HTTP(S) → **very suspicious**.
* `certutil -urlcache -split -f` download + subsequent file execution → **suspicious**.
* PowerShell using `-nop -w hidden -EncodedCommand` or `IEX (New-Object Net.WebClient).DownloadString(...)` → **high priority**.
* Trusted tools executed by unusual parent processes or by non-admin users → **investigate**.
* Fileless persistence often uses WMI event consumers or registry run keys created by script → **search for registry / WMI changes** after detecting in-memory activity.
* Frequent small outbound connections from the same process → possible **beaconing** for C2.

---

## 10) Practical exercise (hands-on)

1. **Hunt for encoded PowerShell**

   * Run the Kibana query for PowerShell encoded commands.
   * Decode any `-EncodedCommand` or base64 strings and review the script.
2. **Hunt for regsvr32 / mshta / rundll32 with URLs**

   * Use the regsvr32/rundll32/mshta query and list hosts & times.
3. **Parent-child anomaly**

   * Find any LOLBin where `parent_process_name` is unusual (e.g., `winword.exe` → `regsvr32.exe`) and build the parent tree.
4. **Cross-correlate network**

   * For hits above, check `network_connection` logs for destination domains/IPs and frequency.
5. **Create 2 ElastAlert rules** (one PowerShell-encoded rule, one parent-anomaly rule) and test with Mordor samples.
6. **Document each finding**: hypothesis, query, evidence, confidence, recommended actions.

---

### Final notes & next steps

* Fileless detection relies on **good telemetry**: process command-line, parent process, scriptblock logging, and network logs. The more fields you collect, the higher your detection fidelity.
* Start with **high-confidence hunts** (encoded commands + network downloads) and iteratively expand to heuristic detection (parent anomalies, long one-liners).
* After each confirmed finding, **tune your ElastAlert rules** and add a dashboard panel that makes future hunts faster.

---

