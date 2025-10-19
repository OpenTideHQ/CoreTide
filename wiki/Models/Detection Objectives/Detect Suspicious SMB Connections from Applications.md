

# 💡Detect Suspicious SMB Connections from Applications

**🚩 Priority : `High`**

🚦 **TLP:GREEN** 🟢 : Limited disclosure, recipients can spread this within their community. Sources may use TLP:GREEN when information is useful to increase awareness within their wider community.

🗡️ **ATT&CK Techniques** :  [T1203 : Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203 'Adversaries may exploit software vulnerabilities in client applications to execute code Vulnerabilities can exist in software due to unsecure coding p'), [T1021.002 : Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002 'Adversaries may use Valid AccountshttpsattackmitreorgtechniquesT1078 to interact with a remote network share using Server Message Block SMB The advers')

---

`🔑 UUID : a8f3c912-4e7d-4b2a-9c3f-8d1e5a6b7c8d` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2025-10-14` **|** `🗓️ Last Modification : 2025-10-14` **|** `👩‍💻 Model author : demo.user@ec.europa.eu` **|** `👥 Contributors : None` **|** `Sharing Organisation : {'uuid': '56b0a0f0-b0bc-47d9-bb46-02f80ae2065a', 'name': 'EC DIGIT CSOC'}` **|** `🧱 Schema Identifier : dom::1.0`

## 💡 Objective

**🏷️ Type** : Threat - Alerts meant for detection cybersecurity threats, and which should eventually trigger Incident Response  

> Detect when applications, particularly Office applications, establish 
> connections to SMB network shares. Threat actors can exploit vulnerabilities 
> in applications to trigger automatic connections to attacker-controlled 
> SMB shares, leading to NTLM credential theft or malicious file retrieval.
> 
> This detection objective focuses on identifying suspicious SMB connection 
> patterns initiated by applications, especially those that require no user 
> interaction and may be used for credential harvesting or lateral movement.
> 

**🎼 Composition** : Independent - No composition performed, each signal can be treated asindependent, unrelated alerts. 

> This detection objective uses two independent signals that can work 
standalone or in combination. The first signal monitors registry access 
patterns indicating SMB provider initialization, while the second tracks 
actual network connections to SMB shares. Together, they provide 
comprehensive coverage of the attack chain.


### 🌊 Related OpenTide Objects

WIP

WIP


## 📡 Signals


### Registry Access to SMB Network Provider Keys

🪪 **UUID** : `b2e9c814-5f8e-4c3a-ad4f-9e2d6b7c8a9b`

> Detects when processes access Windows registry keys associated with 
SMB or WebDAV network providers. This can indicate an application 
attempting to establish a connection to a network share, which may 
be triggered by malicious content such as specially crafted email 
messages or Office documents.

Monitor for access to:
- HKLM\System\CurrentControlSet\Services\LanmanWorkstation\NetworkProvider\Name (SMB)
- HKLM\System\CurrentControlSet\Services\WebClient\NetworkProvider\ProviderPath (WebDAV)

Particular attention should be paid to Office processes or 
SearchProtocolHost.exe accessing these keys, as this may indicate 
exploitation attempts like CVE-2023-23397.


**🔎 Data Visibility**

- **Availability** : Partial
- **Requirements** : `Requires Windows Event Logs with registry auditing enabled, 
specifically Event IDs 4656 and 4663. Security Access Control 
Lists (SACLs) must be configured for "Query Value" operations 
on the monitored registry keys. Endpoint detection telemetry 
from Microsoft Defender for Endpoint or similar EDR solutions.
`

_💾 Possible logsources_

| Name                | Description                            | Data System           | Tenants   | Assets                                                        |
|:--------------------|:---------------------------------------|:----------------------|:----------|:--------------------------------------------------------------|
| DeviceProcessEvents | All traces from workstration processes | defender_for_endpoint | PROD      | - Missing asset documentation for referenced asset JRC::Alpha |

**🧲 Related Entities**

| Name         | Category                                  | Description                                                      |
|:-------------|:------------------------------------------|:-----------------------------------------------------------------|
| Command Line | **Host Entities** : Host Related Entities | Represents the command line arguments used to execute a process. |

**⚠️ Detectors**

| Name   | Description   | Technology                                                                                                                                 | Monitored Assets                                                                                                    | Link                          |
|:-------|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------|:------------------------------|
| ddd    | ...           | **AWS Guardduty** : AWS GuardDuty threat detection service monitoring for malicious activity and unauthorized behavior across AWS accounts | - _AWS S3_ (High Value) : Amazon S3 object storage service hosting application data, backups, and file repositories | [Link](something "something") |

**🌐 Examples**

_❌ No examples mentioned_



### Outbound SMB Connection from Office Applications

🪪 **UUID** : `c3f1d925-6a9f-4d4b-be5a-0f3e7c8d9e0a`

> Detects outbound SMB (TCP 445) network connections initiated by 
Office applications or other productivity software. This behavior 
is suspicious as it may indicate an application automatically 
connecting to an attacker-controlled SMB share to leak NTLM 
credentials or retrieve malicious payloads.

Monitor for:
- Office processes (outlook.exe, winword.exe, excel.exe, etc.) 
  creating outbound connections to TCP port 445
- Connections to external/unusual IP addresses or domains
- Multiple connection attempts in rapid succession
- Connections initiated without user interaction

This signal is particularly effective at detecting exploitation 
of vulnerabilities that force NTLM authentication to remote shares.


**🔎 Data Visibility**

- **Availability** : Complete
- **Requirements** : `Requires network traffic monitoring with the ability to correlate 
process information with network connections. This can be achieved 
through EDR solutions, proxy logs, or network monitoring tools that 
capture process-to-network mappings. Firewall logs showing outbound 
SMB (TCP 445) connections with source process context.
`

_💾 Possible logsources_

| Name                | Description                            | Data System           | Tenants   | Assets                                                        |
|:--------------------|:---------------------------------------|:----------------------|:----------|:--------------------------------------------------------------|
| DeviceProcessEvents | All traces from workstration processes | defender_for_endpoint | PROD      | - Missing asset documentation for referenced asset JRC::Alpha |
| Auth DC             | Authentication against DC machines     | splunk                | PROD      | - Missing asset documentation for referenced asset Active     |

**🧲 Related Entities**

| Name               | Category                                        | Description                                                                                                                                                                                  |
|:-------------------|:------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Process            | **Host Entities** : Host Related Entities       | Represents a running process on a host, including its attributes likeprocess ID and command line.                                                                                            |
| IP Address         | **Network Entities** : Network Related Entities | Represents an IPv4 or IPv6 address associated with a host or networkconnection.                                                                                                              |
| Port               | **Network Entities** : Network Related Entities | Represents a network port, including source and destination ports. Ports are often used to detect unauthorized services or unusual traffic patterns.                                         |
| Hostname           | **Host Entities** : Host Related Entities       | Represents the name of a host or device in the network.                                                                                                                                      |
| Network Connection | **Network Entities** : Network Related Entities | Represents a network connection, including source and destination IPs, ports, and protocols. This entity is critical for detecting suspicious or unauthorized communication between systems. |

**⚠️ Detectors**

_❌ No detectors mentioned_

**🌐 Examples**

_❌ No examples mentioned_



## References



**🕊️ Publicly available resources**

- [_1_] https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397
- [_2_] https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
- [_3_] https://www.picussecurity.com/resource/blog/cve-2023-23397-microsoft-office-outlook-privilege-escalation-vulnerability

[1]: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397
[2]: https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
[3]: https://www.picussecurity.com/resource/blog/cve-2023-23397-microsoft-office-outlook-privilege-escalation-vulnerability

