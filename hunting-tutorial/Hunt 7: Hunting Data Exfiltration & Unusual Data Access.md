Perfect! Let’s move on to **Hunt 7: Hunting Data Exfiltration & Unusual Data Access**. This lesson combines host and network hunting to detect **sensitive data leaving the environment** or being accessed in abnormal ways.

---

## **Hunt 7 — Hunting Data Exfiltration (T1041, T1030, T1074)**

### 1️⃣ Background

Data exfiltration is a **primary goal for many attackers**, especially after credential compromise and lateral movement. Detecting exfiltration early prevents sensitive information leakage.

Common exfiltration methods:

* Network transfer over unusual protocols or ports (HTTP/S, FTP, SMTP, DNS)
* Removable media usage (USB drives)
* Cloud storage uploads (OneDrive, Google Drive, AWS S3)
* Large file reads on sensitive directories

**MITRE ATT&CK IDs:**

* **T1041**: Exfiltration over C2 channels
* **T1030**: Data transfer size anomaly
* **T1074**: File and directory discovery/access

---

### 2️⃣ Step 1: Formulate a Hypothesis

Example hunting hypotheses:

1. “If a host is compromised, attacker may upload sensitive files to external storage over non-standard ports or protocols.”
2. “Hosts reading large volumes of sensitive files outside working hours may indicate exfiltration.”
3. “Multiple failed or successful read attempts to sensitive directories by non-admin accounts may be suspicious.”

---

### 3️⃣ Step 2: Identify Relevant Logs

| Log Source                       | Useful Fields                                                                                            | Purpose                                    |
| -------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| **Sysmon**                       | Event ID 11 (FileCreate), Event ID 12 (FileCreateStreamHash), Event ID 4663 (Security Log – File Access) | Detect file access or creation             |
| **Windows Security Logs**        | Event ID 4663, 4656                                                                                      | Track file read/write attempts             |
| **Zeek/Suricata / Network Logs** | `orig_bytes`, `resp_bytes`, `dest_ip`, `dest_port`, `protocol`                                           | Detect large or unusual data transfers     |
| **PowerShell/Process logs**      | `command_line`, `process_name`                                                                           | Detect scripts/tools used for exfiltration |
| **Audit / Cloud logs**           | S3 bucket access, OneDrive uploads, Google Drive uploads                                                 | Detect external storage access             |

---

### 4️⃣ Step 3: Query Logs in Kibana

**Detect unusual large outbound transfers:**

```text
event_type: "network_connection"
AND dest_ip: NOT [internal IPs]
AND bytes_sent: > 5000000
```

**Detect suspicious file reads on sensitive folders:**

```text
event_id: 4663
AND object_name: "*\\Finance\\*" OR "*\\HR\\*"
AND access_mask: "ReadData" OR "ReadAttributes"
AND user_name: NOT "DomainAdmin"
```

**Detect PowerShell data transfer scripts:**

```text
process_name: "powershell.exe"
AND command_line: "*Invoke-WebRequest* OR *Invoke-RestMethod*"
```

**Detect network file copy via SMB:**

```text
process_name: "powershell.exe" OR "cmd.exe" OR "robocopy.exe"
AND command_line: "*\\\\*"
```

---

### 5️⃣ Step 4: Investigate Anomalies

* Identify **host, user, and time** of suspicious activity.
* Check **file paths** → sensitive directories?
* Look for **unusual destinations** → external IPs, cloud services.
* Check **volume of data** → small vs large transfers.
* Correlate with **previous alerts**:

  * Credential dumping
  * Lateral movement
  * C2 activity

High-confidence findings usually occur when multiple factors align.

---

### 6️⃣ Step 5: Use Dashboards for Context

Add or use panels such as:

* **Top Hosts by Outbound Bytes** → quickly spot unusual data transfers
* **Sensitive File Access Heatmap** → track access frequency by host and user
* **External Connections over Time** → identify spikes matching file reads
* **Process-to-Network Correlation** → identify which process transferred files

---

### 7️⃣ Step 6: Alerts / Detection Rules

**ElastAlert example for large network transfers:**

```yaml
name: "Large Outbound Data Transfer"
type: frequency
index: "mordor-*"
num_events: 1
timeframe:
  hours: 1
filter:
- range:
    bytes_sent:
      gte: 5000000
- query:
    query_string:
      query: "dest_ip: NOT 10.*"
alert:
- "email"
```

**Alert for sensitive file reads outside normal users:**

```yaml
name: "Sensitive File Access by Non-Admin"
type: any
index: "mordor-*"
filter:
- term:
    event_id: 4663
- query:
    query_string:
      query: "object_name: '*\\Finance\\*' OR '*\\HR\\*' AND user_name: NOT 'DomainAdmin'"
alert:
- "email"
```

---

### 8️⃣ Step 7: Practical Hunting Notes

* Data exfiltration hunting is **correlation-heavy**: combine host access + network traffic + previous alerts.
* Large file reads alone may be benign → correlate with:

  * Off-hours access
  * Non-admin users
  * Recent compromise events
* Dashboards are critical to visualize **spikes, patterns, and repeated suspicious activity**.
* Always refine ElastAlert rules as new methods/tools emerge.

---

### Key Takeaways

* Detecting exfiltration requires combining **host logs + network logs + context**.
* High-confidence detection usually comes from **multiple indicators aligning**.
* Alerts should be fine-tuned to reduce false positives but not miss anomalies.
* Hunting is iterative: every finding improves dashboards, queries, and rules.

---

💡 **Practical Exercise for You:**

1. Query your lab for hosts with **large outbound connections**.
2. Check if those hosts accessed **sensitive directories** recently.
3. Identify the **process initiating transfers** (PowerShell, cmd, robocopy, etc.).
4. Cross-reference with prior **credential dumping, lateral movement, and C2 alerts**.
5. Document the hypothesis, queries, and findings.
6. Update ElastAlert rules for similar future exfiltration events.

---
