Let’s move to **Hunt 3: Hunting Credential Dumping (T1003)** using your lab setup. This builds on the PowerShell abuse hunting but dives deeper into **host-level attacks and sensitive data access**.

---

## **Hunt 3: Hunting Credential Dumping (T1003)**

### 1️⃣ Background

Credential dumping is when an attacker extracts account credentials from:

* LSASS process memory (Windows)
* SAM database
* Cached credentials

**Why hunt this:** Compromised credentials allow attackers to move laterally, escalate privileges, and persist in the network.

**MITRE ATT&CK ID:** T1003 – OS Credential Dumping

Your Mordor dataset includes simulated credential dumping events, perfect for hunting practice.

---

### 2️⃣ Step 1: Formulate a Hypothesis

Hunting starts with a clear statement.

**Example hypothesis:**

> “If an attacker has compromised a host, they may attempt to dump credentials using Mimikatz or LSASS memory access.”

---

### 3️⃣ Step 2: Identify Relevant Logs

Focus on host-level logs:

| Log Source                | Useful Fields                    | Why It Matters                                             |
| ------------------------- | -------------------------------- | ---------------------------------------------------------- |
| **Sysmon**                | Event ID 10 (ProcessAccess)      | Detect access to LSASS memory                              |
| **Windows Security Logs** | Event ID 4688 (Process Creation) | Detect suspicious tools like mimikatz.exe                  |
| **PowerShell Logs**       | ScriptBlockLogging               | Detect encoded or suspicious scripts for credential access |

---

### 4️⃣ Step 3: Query Logs in Kibana

Open **Kibana → Discover → mordor-* index**:

**Sysmon process access to LSASS**:

```text
target_process_name: "lsass.exe"
AND process_name: "mimikatz.exe"
```

**Suspicious PowerShell credential dumping**:

```text
process_name: "powershell.exe"
AND command_line: "*Invoke-Mimikatz* OR *sekurlsa*"
```

Look for:

* Processes accessing `lsass.exe`
* Scripts using credential dumping modules
* Hosts executing these tools outside normal administration

---

### 5️⃣ Step 4: Investigate Anomalies

When suspicious events are detected:

* Check **which host and user** triggered the event.
* Correlate with **recent logins**: unusual accounts or remote logins may indicate compromise.
* Look for **repeated LSASS access** → indicates lateral movement or persistent attempts.

---

### 6️⃣ Step 5: Use Dashboards for Context

Open **MITRE Mordor Dashboard**:

* Check **Credential Dumping Histogram** panel.
* Identify spikes or clusters of activity.
* Correlate hosts showing PowerShell abuse and credential access → possible multi-stage attack.

---

### 7️⃣ Step 6: Alerts / Detection Rules

* Open `elastalert/rules/credential_dumping.yml`.
* Example rule snippet for LSASS access:

```yaml
filter:
- term:
    target_process_name: "lsass.exe"
- term:
    process_name: "mimikatz.exe"
```

* Adjust thresholds for your lab data (e.g., alert on **1+ events** per host in 1 hour).

This helps you **automate detection** while hunting.

---

### 8️⃣ Step 7: Practical Hunting Notes

* **Hypothesis-driven hunting**: focus on likely attacker behavior first.
* **Correlation**: PowerShell abuse + LSASS access = high-priority alert.
* **Iterative improvement**: Add new command patterns or processes to rules as you discover more tactics.

---

### Key Takeaways

* Hunting involves **host-centric analysis** using Sysmon & Windows Event Logs.
* Look for **sensitive resource access** (LSASS, SAM, Registry) to detect credential theft.
* Use **dashboards** to identify trends across hosts and time.
* **Refine ElastAlert rules** to automatically detect and notify about suspicious behavior.

---

💡 **Practical Exercise for You:**

1. Query your lab for any `lsass.exe` access events.
2. Identify which hosts/users performed these actions.
3. Check if the same hosts had previous PowerShell abuse events.
4. Note patterns or anomalies and create a hunting report (even a simple table).

---
