# DoS Attack Detection Tool (Defensive Security Project)

## Overview

This project implements a **lightweight, defensive Denial-of-Service (DoS) attack detection tool** that monitors live network traffic and identifies abnormal traffic patterns indicative of potential DoS activity.

The tool is designed for **monitoring and detection only** — it does not generate malicious traffic or perform attacks. It demonstrates core concepts used in intrusion detection systems (IDS), including packet capture, traffic aggregation, and threshold-based alerting.

---

## Problem Statement

Denial-of-Service attacks attempt to overwhelm systems by flooding them with excessive network requests, leading to degraded performance or service unavailability. Detecting these attacks early is critical for maintaining system availability and enabling incident response.

---

## Solution

This project analyses live network traffic in real time and:

* Captures packets from a network interface
* Groups traffic by source IP address
* Measures packet rates within fixed time windows
* Raises alerts when traffic exceeds defined thresholds

The detection logic is intentionally simple, explainable, and configurable, making it suitable for learning, experimentation, and portfolio demonstration.

---

## How It Works

1. **Packet Capture**
   Uses the Scapy library to sniff live network packets on a Linux system.

2. **Traffic Aggregation**
   Incoming packets are grouped by source IP address, and packet counts are tracked per IP.

3. **Time-Window Analysis**
   Traffic is analysed over fixed one-second windows to calculate packets per second.

4. **Threshold-Based Detection**
   If a source IP exceeds a configurable packet-rate threshold, the tool raises an alert indicating a potential DoS condition.

---

## Technologies Used

* Python 3
* Scapy
* Linux (Kali Linux VM)
* VirtualBox

---

## Detection Parameters

The detector uses configurable parameters:

* **Time window:** 1 second
* **Alert threshold:** 100 packets per second per source IP

These values can be tuned to adjust detection sensitivity and reduce false positives.

---

## Testing Methodology

Testing was conducted in a **controlled local lab environment only**.

* High-frequency ICMP traffic was generated against `127.0.0.1` (localhost)
* Packet rates exceeded 500 packets per second to validate alert triggering
* No external systems or networks were targeted

This approach ensured safe and ethical testing while validating detection accuracy.

---

## Example Alert Output

```
[ALERT] Possible DoS detected from 127.0.0.1 (487 packets/sec)
```

---

## Limitations

* Uses static thresholds rather than adaptive baselines
* Does not differentiate between legitimate high traffic and malicious traffic
* Detection is based on packet rate only, without deep protocol inspection

These limitations are intentional to keep the implementation simple and transparent.

---

## Future Improvements

* Sliding-window or rolling-average detection
* Baseline learning and anomaly-based detection
* Protocol-specific detection (e.g. TCP SYN floods)
* Alert logging and visualisation
* Integration with firewall rules or SIEM tools

---

## Security and Ethics

This project focuses exclusively on **defensive security techniques**. All testing was performed in an isolated environment, and no attack traffic was generated against external systems.

---

