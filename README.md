# Threat Hunting Docker Lab

This repository contains a **Threat Hunting lab** built with Docker, using the **ELK Stack (Elasticsearch, Logstash, Kibana)** and **ElastAlert2**, pre-configured with dashboards and detection rules for the **Mordor dataset**. It is designed for threat hunting, detection engineering, and SOC training.

---

## Table of Contents

- [Requirements](#requirements)
- [Folder Structure](#folder-structure)
- [Setup Instructions](#setup-instructions)
- [Importing Mordor Dataset](#importing-mordor-dataset)
- [Verify Installation](#verify-installation)
- [Using the Lab](#using-the-lab)
- [ElastAlert Rules](#elastalert-rules)
- [Kibana Dashboards](#kibana-dashboards)
- [Stopping and Cleaning Up](#stopping-and-cleaning-up)

---

## Requirements

- Docker ≥ 24.0
- Docker Compose ≥ 2.20
- Git (to clone repository)
- Mordor dataset files (JSON logs, PCAP/Zeek/Suricata captures)

---

## Folder Structure

```
Threat-Hunting-Docker-Lab/
├── docker-compose.yml
├── logstash/
│   └── pipeline/
│       └── mordor.conf
├── elastalert/
│   └── opt/
│       └── rules/
|           └── mordor_suspicious.yml
│       └── config.yml
├── kibana/
│   └── dashboards/
│       └── mordor_dashboard.ndjson
├── setup/
│   └── import_dashboards.sh
└── mordor/
    └── (place Mordor dataset JSON files here)

```

---

## Setup Instructions

1. **Clone the repository**
```bash
git clone https://github.com/pbmundas/Threat-Hunting-Docker-Lab.git
cd Threat-Hunting/Lab
```

2. **Place Mordor dataset files**

* Copy JSON log files into a folder like `Lab/mordor-logs/`.
* If using PCAPs:
  * Process them with **Zeek** or **Suricata** to convert into JSON.
  * Place processed JSON files in `Lab/network-logs/`.

3. **Start Docker services**
```bash
docker compose up -d
```

4. **Verify containers are running**
```bash
docker ps
```
Expected containers:
* `threathunting-elasticsearch-1`
* `threathunting-kibana-1`
* `threathunting-logstash-1`
* `elastalert`
* (`elk-setup` may run one-time dashboard import)

---

## Importing Mordor Dataset

1. JSON logs (Sysmon, Windows event logs) can be ingested by **Logstash** directly keeping those JSON files in mordor folder (Currently there are limited sets as there is a size constraints).
https://github.com/UraSecTeam/mordor/tree/master/datasets
---

## Verify Installation

1. **Check Elasticsearch**
```bash
curl http://localhost:9200
```
Should return JSON with cluster info.

2. **Access Kibana**
* Open browser: [http://localhost:5601](http://localhost:5601)
* Go to **Discover** → confirm indices like `mordor-*` or `network-*` (Create a dataview if these are not there, just create a index mordor* with any name your wish).
* Go to **Dashboard** → verify `MITRE + Mordor Dashboard`.

3. **Check Logstash logs**
```bash
docker logs threathunting-logstash-1 -f
```
Ensure logs are being ingested without errors.

4. **Check ElastAlert**
```bash
docker logs elastalert -f
```
You should see rules being loaded successfully.

---

## Using the Lab

* **Visualize TTPs**: Use Kibana dashboards to explore:
  * Suspicious PowerShell commands
  * Credential dumping attempts
  * C2 network connections
* **Filter logs**: By host, user, or IP to perform threat hunting exercises.
* **Trigger alerts**: Use Mordor dataset events to test ElastAlert detection rules.

---

## ElastAlert Rules

* `powershell_suspicious.yml` → Detects suspicious PowerShell commands (T1059.001)
* `credential_dumping.yml` → Detects LSASS/mimikatz style credential dumping (T1003)
* `c2_activity.yml` → Detects unusual network connections indicative of C2 (T1071)

---

## Kibana Dashboards

* `mitre_mordor_dashboard.ndjson` → MITRE ATT&CK visualizations for Mordor logs
* Panels include:
  * PowerShell command table
  * Credential dumping histogram
  * C2 connections pie chart

**Import manually** (if not done automatically by `elk-setup`):
1. Go to **Stack Management → Saved Objects → Import**
2. Upload `dashboards/mitre_mordor_dashboard.ndjson`

---

## Stopping and Cleaning Up

1. Stop all containers:
```bash
docker compose down
```

2. (Optional) Remove Docker volumes:
```bash
docker volume rm threathunting_esdata
```

---

## Notes

* Update ElastAlert rules in `elastalert/rules/` to add custom detections.
* Use Zeek/Suricata for realistic network simulation with PCAPs.
* Always check Docker container logs for troubleshooting ingestion or alerts.

