Let’s dive into **Lesson 2: Hunting PowerShell Abuse (T1059.001)** using your lab. We’ll go step by step, so you can understand the practical workflow.

---

## **Lesson 2: Hunting PowerShell Abuse**

### 1️⃣ Background

Attackers frequently abuse PowerShell for:

* Downloading or executing malware.
* Running scripts to gather credentials.
* Moving laterally in the network.

**MITRE ATT&CK ID:** T1059.001 – Command and Scripting Interpreter: PowerShell

Your Mordor dataset already simulates some of these events, so it’s perfect for hunting practice.

---

### 2️⃣ Step 1: Formulate a Hypothesis

A hunting hypothesis is a **statement you want to prove or disprove**, based on knowledge of attacker behavior.

**Example hypothesis:**

> “If an attacker is present on a host, they may use PowerShell to download or execute suspicious scripts.”

---

### 3️⃣ Step 2: Identify Relevant Logs

For this hypothesis, look at:

* **Sysmon Process Creation logs**

  * `process_name` → powershell.exe
  * `command_line` → parameters used in execution
* **Windows Event Logs**

  * Event ID 4688 → process creation
* **Network logs (optional)**

  * Any outgoing connections from PowerShell scripts

---

### 4️⃣ Step 3: Query Logs in Kibana

Open **Kibana → Discover → mordor-*** index:

* Filter for PowerShell process creation:

```text
process_name: "powershell.exe"
```

* Add command line filter for suspicious patterns:

```text
command_line: "*-nop* OR *-exec bypass* OR *Invoke-WebRequest*"
```

This helps you detect PowerShell scripts executed with:

* No profile (`-nop`)
* Execution policy bypass (`-exec bypass`)
* Direct downloads (`Invoke-WebRequest`)

---

### 5️⃣ Step 4: Investigate Anomalies

Once the query results are shown:

* Look for **unusual hosts or users** executing PowerShell.
* Check **timestamp patterns** – PowerShell running outside normal working hours is suspicious.
* Analyze **command line parameters** – encoded commands (base64) are often malicious.

💡 Tip: Copy suspicious command lines and decode them using online base64 decoders for further analysis.

---

### 6️⃣ Step 5: Validate Findings

Questions to ask:

* Has this host executed PowerShell like this before?
* Is this user normally running PowerShell commands?
* Are there matching network connections (C2-like activity)?

If yes → you’ve likely found malicious behavior.
If no → it might be benign but worth monitoring.

---

### 7️⃣ Step 6: Use Dashboards for Context

Open **MITRE Mordor Dashboard**:

* Look at **PowerShell command table** panel.
* Identify hosts with multiple suspicious commands.
* Compare with **credential dumping or C2 panels** to see if this is part of a larger attack chain.

---

### 8️⃣ Step 7: Trigger Alerts / Update Rules

* Open your `elastalert/rules/powershell_suspicious.yml`.
* Verify it’s detecting events matching your query.
* Adjust thresholds or patterns to reduce false positives:

```yaml
filter:
- term:
    process_name: "powershell.exe"
- query:
    query_string:
        query: "command_line: *-nop* OR *-exec bypass* OR *Invoke-WebRequest*"
```

---

###  Key Takeaways

* Start hunting with a **hypothesis** based on attacker TTPs.
* Identify **relevant log sources** (Sysmon, Event Logs, Network).
* Use **Kibana queries** to detect anomalies.
* Visualize activity in **dashboards** for correlation.
* **Refine ElastAlert rules** to catch similar activity automatically in the future.

---

💡 **Practical Exercise for You:**

1. Formulate a new PowerShell hypothesis: e.g., “PowerShell executed by SYSTEM user at night.”
2. Run a query in Kibana to test it.
3. Identify suspicious commands.
4. Note the host, user, and command line.
5. Check dashboard panels to see if this host has other malicious activity.

---

