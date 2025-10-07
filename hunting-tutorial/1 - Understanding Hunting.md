Start your **practical threat hunting journey** from zero. I’ll guide you step by step, using your **Docker-based ELK + ElastAlert2 lab** as the hands-on platform. I’ll break this into multiple hunting steps, each with practical exercises, so you can truly understand how threat hunting works in real SOC scenarios.

Let’s start **Hunt 1: Foundations of Threat Hunting**.

---

## **Hunt 1: Understanding Threat Hunting Fundamentals**

### 1️⃣ What is Threat Hunting?

Threat hunting is a **proactive process** where analysts look for malicious activity **before alerts are triggered**. Unlike traditional SIEM monitoring, which reacts to alerts, hunting:

* Searches for subtle anomalies in logs and network activity.
* Hypothesizes attacker behavior (TTPs).
* Investigates and validates findings.
* Improves detection rules (feedback loop).

---

### 2️⃣ Core Components in Your Lab

Your Docker setup already has everything you need:

| Component         | Purpose for Hunting                                        |
| ----------------- | ---------------------------------------------------------- |
| **Elasticsearch** | Stores and indexes all logs for fast querying.             |
| **Logstash**      | Ingests logs from Mordor dataset, PCAP, or JSON.           |
| **Kibana**        | Visualizes logs, builds dashboards, and performs searches. |
| **ElastAlert2**   | Generates alerts based on detection rules.                 |

---

### 3️⃣ Log Sources You Can Use

Threat hunting relies heavily on logs. Here’s what you have and why they matter:

1. **Sysmon (Windows)** – Detects process creation, registry changes, network connections.
2. **Windows Event Logs** – Tracks authentication, process events, security policy changes.
3. **Zeek / Suricata (Network)** – Network traffic metadata; C2 connections, scans, lateral movement.
4. **Mordor JSON Logs** – Pre-generated attack simulations: PowerShell abuse, credential dumping, C2 activity.

**Key idea:** Every log is a piece of the puzzle. Effective hunting means combining multiple log sources to see the full attack picture.

---

### 4️⃣ Hunting Features in Your Lab

* **Logs** → raw investigation and search.
* **Dashboards** → visualize suspicious patterns or TTPs.
* **Alerts (ElastAlert)** → notify when predefined suspicious activity occurs.
* **Filters & Queries** → narrow down by host, user, IP, process, etc.

---

### 5️⃣ Threat Hunting Workflow

Here’s a simple **practical workflow**:

1. **Create a hypothesis** → e.g., “An attacker may use PowerShell to download malware.”
2. **Identify relevant logs** → Sysmon process creation, network logs, Windows events.
3. **Search logs in Kibana** → build queries or filters.
4. **Investigate anomalies** → look for unusual commands, failed logins, or unknown hosts.
5. **Validate & escalate** → confirm if it’s malicious, then trigger alerts.
6. **Refine detections** → add new ElastAlert rules based on findings.

---

### 6️⃣ Example Starting Point in Your Lab

* Open **Kibana → Discover**.
* Select **mordor-* index**.
* Filter for suspicious PowerShell commands:

  ```text
  NewProcessName: "powershell.exe" AND CommandLine: "*Invoke-WebRequest*"
  ```
* Observe patterns → see if any hosts executed unusual commands.

---

### Key Takeaways

* Logs are your “sensor data” for hunting.
* Dashboards help you **spot anomalies visually**.
* Alerts are **reactive support** to hunting, not the primary hunting tool.
* Threat hunting is iterative → hypothesis → investigation → validation → feedback.

---

💡 **Next Lesson Preview**:
We’ll start your **first hands-on threat hunting exercise** with **PowerShell abuse detection** from Mordor logs. You’ll learn to create a hypothesis, hunt using Kibana, and generate actionable findings.

---
