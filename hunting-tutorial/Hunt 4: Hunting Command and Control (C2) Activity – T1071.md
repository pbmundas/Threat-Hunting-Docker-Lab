Let’s move to **Hunt 4: Hunting Command and Control (C2) Activity – T1071**. This lesson shifts focus from host-based hunting to **network-based hunting**, combining process events with network logs.

---

## **Hunt 4: Hunting C2 Activity (T1071)**

### 1️⃣ Background

Command and Control (C2) is how attackers maintain **remote control over compromised hosts**. Detecting C2 activity early is critical to prevent data exfiltration or lateral movement.

**MITRE ATT&CK ID:** T1071 – Application Layer Protocol

Common C2 indicators include:

* Unusual outbound connections
* Traffic to unknown or suspicious IPs/domains
* Uncommon ports/protocols
* Encrypted traffic to unusual hosts

Your lab can simulate C2 activity using Mordor dataset logs and network captures via Zeek/Suricata.

---

### 2️⃣ Step 1: Formulate a Hypothesis

Example hunting hypothesis:

> “If a host is compromised, it may attempt C2 communication to an external IP using unusual protocols or ports.”

---

### 3️⃣ Step 2: Identify Relevant Logs

* **Sysmon Network Connection Logs (Event ID 3)**

  * Fields: `Source IP`, `Destination IP`, `Destination Port`, `Protocol`, `Process Name`
* **Zeek/Suricata Network Logs**

  * Fields: `uid`, `orig_h`, `resp_h`, `service`, `proto`, `duration`, `bytes`
* **Process Logs**

  * Check which process is initiating the connections (e.g., PowerShell, wmic.exe, or unknown binaries)

---

### 4️⃣ Step 3: Query Logs in Kibana

**Basic network hunt**:

```text
event_type: "network_connection"
AND dest_ip: NOT [internal IP range]
AND process_name: "powershell.exe"
```

* `dest_ip NOT in internal range` → focuses on external connections
* Filter by **unusual ports** (e.g., 8080, 8443, 9001) or uncommon protocols.
* Look for repeated connections from **the same host** → beaconing behavior.

---

### 5️⃣ Step 4: Investigate Anomalies

When suspicious events are detected:

* Identify **host and user** initiating the connection.
* Correlate with **process creation logs** → e.g., PowerShell or malicious binary.
* Check **frequency** → automated beaconing may occur every few seconds/minutes.
* Look for **destination IP reputation** → is it a known malicious host?

---

### 6️⃣ Step 5: Use Dashboards for Context

Open **MITRE Mordor Dashboard**:

* **C2 Connections Pie Chart** → shows hosts connecting to external IPs
* **Timeline Panel** → visualize beaconing over time
* **Process Correlation** → check which process initiated the suspicious network activity

This helps you **see the bigger picture** beyond individual logs.

---

### 7️⃣ Step 6: Alerts / Detection Rules

Your `elastalert/rules/c2_activity.yml` can be adjusted:

```yaml
filter:
- term:
    process_name: "powershell.exe"
- query:
    query_string:
        query: "dest_ip: NOT 10.* OR 192.168.*"
```

* Set frequency thresholds to catch **beaconing behavior**.
* Include other suspicious processes for broader coverage (wmic.exe, regsvr32.exe, mshta.exe).

---

### 8️⃣ Step 7: Practical Hunting Notes

* Network hunting is **correlation-heavy**: combine process logs + network traffic + host behavior.
* Use dashboards to **triage multiple hosts** quickly.
* Hunting is iterative → refine queries based on anomalies, not just static rules.

---

### Key Takeaways

* C2 hunting focuses on **outbound, suspicious, or anomalous network connections**.
* Combine **process + network logs** for context.
* Use **dashboards** to visualize patterns across hosts.
* Refine alerts for automated detection of **high-confidence C2 activity**.

---

💡 **Practical Exercise for You:**

1. Query Mordor/Zeek logs for external connections initiated by PowerShell or unknown processes.
2. Identify hosts repeatedly connecting to external IPs.
3. Visualize connections over time in Kibana.
4. Correlate with previous PowerShell abuse or credential dumping findings.
5. Update ElastAlert rule thresholds to detect suspicious network activity.

---

