Let’s move to **Hunt 5: Hunting Lateral Movement (T1021)**. This is a critical part of threat hunting because attackers often try to move from one host to another after compromising an initial endpoint.

---

## **Hunt 5: Hunting Lateral Movement (T1021)**

### 1️⃣ Background

**Lateral movement** allows attackers to:

* Expand access within the network.
* Find sensitive systems.
* Maintain persistence.

Common tools and methods include:

* **PsExec**, **WMIC**, **PowerShell remoting**, **RDP**, **SMB shares**.
* Using **stolen credentials** from previous steps (T1003).

**MITRE ATT&CK ID:** T1021 – Remote Services

---

### 2️⃣ Step 1: Formulate a Hypothesis

Example hunting hypotheses:

1. “If a host is compromised, the attacker may attempt to connect to other hosts using SMB or RDP.”
2. “Hosts executing PsExec with remote targets outside normal admin operations are suspicious.”

---

### 3️⃣ Step 2: Identify Relevant Logs

Key logs to monitor:

| Log Source                | Useful Fields                                                                          | Purpose                                 |
| ------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------- |
| **Sysmon**                | Event ID 3 (Network Connection), Event ID 11 (FileCreate), Event ID 10 (ProcessAccess) | Detect remote tool usage                |
| **Windows Security Logs** | Event ID 4624 (Logon), Event ID 4648 (Explicit Credential Use)                         | Detect unusual remote logins            |
| **Network Logs**          | Zeek/Suricata traffic                                                                  | Detect SMB, RDP, or unusual connections |

---

### 4️⃣ Step 3: Query Logs in Kibana

**Hunting SMB lateral movement**:

```text
process_name: "psexec.exe"
AND dest_ip: NOT [internal admin hosts]
```

**Hunting RDP connections**:

```text
event_id: 4624
AND logon_type: 10
AND source_ip: NOT [trusted admin IPs]
```

**Hunting WMI/PowerShell remoting**:

```text
process_name: "wmic.exe" OR "powershell.exe"
AND command_line: "*-ComputerName*"
```

---

### 5️⃣ Step 4: Investigate Anomalies

When suspicious events are detected:

* Identify **source host** (where attacker originated).
* Identify **target hosts** (where attacker attempted to move).
* Correlate with **credential dumping** events → likely the same attacker.
* Look for **unusual time activity** (outside business hours).

---

### 6️⃣ Step 5: Use Dashboards for Context

* Add a panel for **remote login events** over time.
* Visualize **host-to-host connections** (source → destination).
* Identify **clusters of activity** → may indicate lateral movement attempts by the same attacker.

---

### 7️⃣ Step 6: Alerts / Detection Rules

Example ElastAlert rule for PsExec detection:

```yaml
filter:
- term:
    process_name: "psexec.exe"
- query:
    query_string:
        query: "dest_ip: NOT 10.*"
```

* Trigger on **single high-confidence events** or repeated connections within 1 hour.
* Add processes like `wmic.exe`, `powershell.exe` for broader coverage.

---

### 8️⃣ Step 7: Practical Hunting Notes

* Lateral movement hunting **correlates multiple hosts**.
* Look for **patterns in tool usage** combined with **credential theft**.
* Use **dashboards** to visualize lateral attack paths and prioritize investigation.

---

### Key Takeaways

* Lateral movement is often **post-compromise**, so it ties host + network hunting together.
* Correlate **credentials, process creation, and network connections** to detect attacks.
* Refine rules to automatically detect lateral movement attempts.
* Dashboards are invaluable for **seeing the bigger picture** across multiple hosts.

---

💡 **Practical Exercise for You:**

1. Query Mordor/Zeek logs for PsExec, WMIC, or PowerShell remoting events.
2. Identify **source and target hosts**.
3. Check if these hosts were involved in previous PowerShell abuse or credential dumping events.
4. Map a **host-to-host lateral movement path**.
5. Adjust ElastAlert rules to detect similar lateral movement automatically.

---
