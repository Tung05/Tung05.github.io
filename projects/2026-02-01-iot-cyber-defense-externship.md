---
date: 2026-02-01
layout: page
tags: [cybersecurity, ai, internship]
---

[← Back to Projects](/projects/)

## Overview

Participating in a hands-on IoT Cyber Defense externship focused on securing real-world IoT infrastructure for a simulated 500-room smart hotel environment. The program covers threat modeling, secure pipeline design, device identity management, encryption, replay attack prevention, monitoring, and AI-based anomaly detection.

This externship simulates the responsibilities of a security engineer defending production IoT systems.

---

## Project 1: IoT Systems & Threat Modeling ✅

### Deliverable
📄 [View Threat Model (PDF)](../images/Tung%20Nguyen%20-%20Threat%20Model%20.pdf)

### Objective
Develop a structured threat model for a simulated smart water management system supporting a 500-room IoT-enabled hotel.

### Work Completed
- Applied the CIA Triad to IoT infrastructure
- Identified six primary IoT attack vectors
- Used STRIDE methodology to systematically uncover vulnerabilities
- Documented risks across authentication, message integrity, and device trust boundaries

### Key Skills
- Threat modeling
- STRIDE framework
- Risk analysis
- Security architecture evaluation

### Key Takeaway
Threat modeling forces clarity. Many vulnerabilities were not obvious until system boundaries and trust relationships were explicitly mapped.

---

## Project 2: Python for IoT Security 🔄 (In Progress)

### Deliverable
📄 [Download Sample Dataset](https://drive.google.com/file/d/1w_RAv-Gv0Oe6Dn-4y5dmNm1y3tbl5t91/view?usp=drive_link)

### Objective
Built a mock Hydroficient HYDROLOGIC water sensor to simulate realistic IoT telemetry for downstream security testing and anomaly detection.

### Implementation Highlights
- Designed a `WaterSensor` class in Python
- Generated ISO 8601 UTC timestamps
- Implemented sequential counters for replay attack detection
- Simulated realistic pressure and flow values
- Injected controlled anomalies:
  - Leak (abnormally high flow rate)
  - Blockage (pressure imbalance)
  - Stuck sensor (static readings)
- Generated and exported 100 structured JSON records

### Sample Output

```json
{
  "device_id": "GM-HYDROLOGIC-01",
  "timestamp": "2026-02-19T03:35:05.551904+00:00",
  "counter": 6,
  "pressure_upstream": 81.3,
  "pressure_downstream": 75.9,
  "flow_rate": 99.5
}
```

---

## Project 3: Building an Insecure MQTT Pipeline 🚧 (In Progress)

### Objective
Construct and exploit an intentionally insecure MQTT data pipeline to understand real-world interception, tampering, and replay risks in IoT environments.

### Current Focus
- Setting up local MQTT broker
- Configuring publisher and subscriber clients
- Transmitting unencrypted telemetry data
- Preparing environment for packet interception and traffic analysis

### Planned Exploration
- Capturing MQTT traffic using packet analysis tools
- Demonstrating message interception and tampering
- Evaluating weaknesses in unauthenticated communication

### Expected Skills
- MQTT protocol fundamentals  
- Network traffic analysis  
- Packet inspection  
- IoT communication security  

---

## Upcoming Projects (Coming Soon)

### Project 4: Securing the Pipeline with TLS
Implement TLS encryption and evaluate security-performance tradeoffs.

### Project 5: Device Identity & Provisioning
Implement certificate-based authentication and prevent rogue devices.

### Project 6: Replay Attack Simulation & Defense
Simulate replay attacks and implement timestamp and counter-based defenses.

### Project 7: Real-Time Security Dashboard
Build a live security monitoring dashboard using Streamlit.

### Project 8 (Optional): AI-Powered Anomaly Detection
Apply Isolation Forest to detect spoofed readings, timing inconsistencies, and anomalous IoT behavior.

---

## Technologies Used

- Python
- Pandas
- MQTT
- TLS
- X.509 Certificates
- Streamlit
- Isolation Forest (Machine Learning)
- STRIDE Threat Modeling

---

## Status

Currently progressing through the program (Week 3 of 8).
Ongoing updates will be added as projects are completed.