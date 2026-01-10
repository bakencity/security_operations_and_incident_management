
# COMP5002 – Security Operations & Incident Management  
## Assessment 2: BOTSv3 Incident Analysis  
### Author: (pg) Kehinde Akintade  
### Student ID: 10960353  
### Year: 2025  

---

# 1. Introduction  

Modern organisations are increasingly exposed to advanced cyber threats due to expanding cloud environments, hybrid infrastructures, and automation‑enabled attack capabilities. Security Operations Centres (SOCs) play a central role in defending digital assets by continuously monitoring systems, detecting anomalies, and coordinating incident response. SOC teams integrate people, processes, and technologies to reduce risk, maintain situational awareness, and support organisational resilience [1].

This investigation applies SOC principles to analyse the BOTSv3 dataset in Splunk. Guided by the NIST SP 800‑61 Rev.3 Incident Response Framework, the analysis focuses on identifying indicators of compromise (IOCs), reconstructing adversarial behaviour, and assessing weaknesses exploited during the attack [3]. The report aligns with industry best practice and demonstrates how SOC methodologies support structured, evidence‑driven intrusion investigation.

---

# 2. SOC Roles & Incident Handling Reflection  

A modern SOC operates through a tiered analyst model:

- **Tier 1 Analysts** perform alert triage, validate security events, and escalate genuine threats based on severity and confidence [4].  
- **Tier 2 Analysts** perform deeper investigation, cross‑correlating multi‑source logs to determine root causes and attack paths.  
- **Tier 3 Analysts / Threat Hunters** conduct advanced forensics, analyse malware behaviour, develop detection content, and support complex incident response workflows [5].

This structure aligns with the NIST Incident Response Lifecycle, which consists of Preparation, Detection & Analysis, Containment/Eradication/Recovery, and Post‑Incident Activity [6]. Following these phases ensures consistent, timely, and repeatable response actions.  

This assessment mirrors SOC Tier 2 workflows by employing structured SPL queries, correlating endpoint, network, email, and cloud telemetry, and interpreting attacker behaviour within the kill‑chain framework.

---

# 3. Installation & Data Preparation  

## 3.1 Installation  
The SOC environment was prepared as follows:

1. Installed **VirtualBox** on macOS and deployed **Ubuntu 22.04 LTS**.  
   - *Screenshot:* `evidence/evidence_virtualbox.png`

2. Installed **Splunk Enterprise** using the Linux `.tgz` package.  
   - *Screenshot:* `evidence/splunk_install.png`

3. Configured an administrative Splunk account and launched Splunk Web.

## 3.2 Data Preparation  
- Downloaded the **BOTSv3 dataset** from the official repository:  
  https://github.com/splunk/botsv3  
- Added the dataset to Splunk via indexing configuration.  
- Validated dataset availability with:
index=botsv3 earliest=0
This ensured full visibility of historical data without time restrictions.  

- *Screenshot:* `evidence/evidence_botsv3_data.png`

---

# 4. Methodology  

This investigation combined NIST‑aligned incident handling procedures with SIEM‑driven forensic analysis using Splunk SPL.

## 4.1 Tools & Sources  
- **Splunk SIEM** for log correlation and event analytics [1].  
- **Microsoft O365 Management Logs** for OneDrive activity.  
- **SMTP stream logs** for mail‑borne malware.  
- **Sysmon logs** for identifying process execution and hashing [4].  
- **osquery logs** for Linux account and port activity [5].

## 4.2 Analytical Approach  
### Detection & Analysis  
SPL queries were constructed to identify malicious indicators across:
- O365 OneDrive uploads  
- Email attachment flows  
- Sysmon process execution  
- Linux account creation  
- Network port activity  

### Correlation  
Events were correlated across:
- User accounts  
- Filenames  
- Timestamps  
- MD5 hashes  
- Process IDs  
- Network ports  
- Cloud user‑agents  

This multi‑domain correlation reflects standard SOC Tier 2 investigative processes.

### Kill‑Chain Mapping  
Adversary actions were mapped onto the kill‑chain:
1. Delivery  
2. Execution  
3. Persistence  
4. Reconnaissance  
5. Cloud abuse  

## 4.3 Evidence Integration  
Each SPL query is supported by screenshots stored in the `evidence/` folder for auditability and verification.

---

# 5. Guided Questions (Results & Evidence)

| No. | Question | Answer | Evidence |
|-----|----------|--------|---------|
| 1 | User agent that uploaded malicious link | `Mozilla/5.0 … NaenaraBrowser/3.5b4` | `evidence/evidence_q1.png` |
| 2 | Macro‑enabled malware attachment | `Frothly‑Brewery‑Financial‑Planning‑FY2019‑Draft.xlsm` | `evidence/evidence_q2.png` |
| 3 | Embedded executable | `HxTsr.exe` | `evidence/evidence_q3.png` |
| 4 | Linux account password | `ilovedavidverve` | `evidence/evidence_q4.png` |
| 5 | Windows malicious account | `svcvnc` | `evidence/evidence_q5.png` |
| 6 | Assigned groups | `administrators,user` | `evidence/evidence_q6.png` |
| 7 | PID on leet port | `14356` | `evidence/evidence_q7.png` |
| 8 | MD5 of scanning tool | `586ef56f4d8963dd546163ac31c865d7` | `evidence/evidence_q8.png` |

---

# 6. Narrative of the Intrusion  

### **Delivery**  
A malicious `.xlsm` attachment was delivered to a user via email, exploiting macro functionality to initiate the attack.

### **Execution**  
Sysmon logs identified execution of the embedded payload `HxTsr.exe`, signalling successful malware deployment.

### **Persistence**  
Two illicit accounts were created:
- **Windows:** `svcvnc` (privileged)  
- **Linux (hoth):** account with password `ilovedavidverve`  

These actions demonstrate attacker persistence through credential manipulation.

### **Reconnaissance / C2**  
A process listening on **port 1337** suggested internal reconnaissance or backdoor communications.

### **Cloud Abuse**  
A suspicious OneDrive file upload via **NaenaraBrowser**, a rare user agent, expanded the compromise into cloud infrastructure.

---

# 7. Prevention & Response Recommendations  

### Email Controls  
Deploy attachment sandboxing, Safe Attachments, Safe Links, and enforce signed-macro policies to block malicious documents [2].

### Endpoint Hardening  
Use **Windows Defender Application Control** and enriched Sysmon configurations to enforce execution control and improve visibility [3][4].

### Identity Governance  
Apply least privilege, MFA, LAPS, and Linux sudo/PAM restrictions to prevent unauthorised persistence [5].

### Network & Cloud Monitoring  
Implement NDR, egress filtering, and CASB-based cloud anomaly detection to prevent misuse of cloud platforms [1].

### SOC Playbook Improvements  
Update playbooks to include:
- Macro malware  
- Windows + Linux account anomalies  
- Leet-port listeners  
- Cloud user-agent anomalies  
Align these updates with NIST’s continuous improvement cycle [6].

---

# 8. Conclusion  

The investigation demonstrates that effective SIEM-driven correlation enables the reconstruction of complex adversarial activity across email, endpoint, cloud, and operating system layers. This multi-domain attack highlights the necessity of robust identity governance, endpoint controls, email filtering, and cloud monitoring.

Applying the recommended defence strategies will significantly reduce the risk of similar intrusions. Consistent with NIST SP 800‑61 Rev.3 guidance, organisations must continuously refine their SOC capabilities through structured lessons learned and detection-rule updates [6].

---

# 9. Video Presentation  

https://youtu.be/yEVfpLK0xFQ 

---

# 10. Evidence Folder Structure  


evidence/
│── evidence_q1.png
│── evidence_q2.png
│── evidence_q3.png
│── evidence_q4.png
│── evidence_q5.png
│── evidence_q6.png
│── evidence_q7.png
│── evidence_q8.png

---

# 11. References (IEEE Style)

[1] M. Scapicchio, “What is a Security Operations Center (SOC)?,” IBM Think, 2025.  
    Available: https://www.ibm.com/think/topics/security-operations-center  

[2] K. A. Cochran, *CompTIA CySA+ Certification Companion*, Springer/Apress, 2025.  
    Available: https://link.springer.com/book/10.1007/979-8-8688-1495-2  

[3] A. Nelson et al., *NIST SP 800‑61 Rev.3*, NIST, 2025.  
    Available: https://csrc.nist.gov/pubs/sp/800/61/r3/final  

[4] J. Goldstein, “Incident Response Steps & Phases,” SentinelOne, 2025.  
    Available: https://www.sentinelone.com/cybersecurity-101/services/incident-response-steps-phases/  

[5] J. Muniz et al., *Security Operations Center: Building, Operating, and Maintaining Your SOC*, Cisco Press, 2015.  
    Available: https://www.ciscopress.com/store/security-operations-center-building-operating-and-maintaining-9780134052014  

[6] A. Nelson et al., *NIST SP 800‑61 Rev.3*, NIST, 2025.  
    Available: https://csrc.nist.gov/pubs/sp/800/61/r3/final  

---

