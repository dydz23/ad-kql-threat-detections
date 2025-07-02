# T1595 – Active Scanning (Reconnaissance)

### 💥 Description
This detection identifies excessive outbound network connections within a short time window, potentially indicating **active scanning behavior** like port sweeps or service discovery.

### 📘 MITRE Info
- Tactic: Reconnaissance
- Technique: [T1595 – Active Scanning](https://attack.mitre.org/techniques/T1595/)

---

### 📊 Data Sources Used
- Sysmon Event ID 3 (Network Connect)
- Security Event ID 5156 (WFP network connect)
- Defender `DeviceNetworkEvents`

---

### 🔍 KQL Example: Detecting Port Scan (Sysmon)

```kql
Event
| where EventID == 3
| summarize PortCount = dcount(DestinationPort) by SourceIp, bin(TimeGenerated, 1m)
| where PortCount > 100
