# 🔍**Sudden Network Slowdowns**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ab796c31-b368-4294-af03-cae6f68f4f3f" />


## Example Scenario:
The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally. All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment.

NOTE: I spun up a VM on Azure, and then onboarded it to Microsoft Defender for Endpoint. This will act as the suspicious host.

## Goal:
Identify if someone on network is either downloading large files or doing some kind of port scan against hosts in the network.

---

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:**  danscenario3lab has been found failing several connection requests against itself and other hosts.
  
   - **Detection Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "danscenariolab"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

## Sample Output:

<img width="1210" height="516" alt="Screenshot 2026-02-27 110156" src="https://github.com/user-attachments/assets/76aa0459-b2b0-4e20-9e8f-c3228690e900" />



---

### Port Scan Detection

After observing failed connection requests from our suspected host (10.1.0.140) in sequential order. I observed a port scan was taking place due to the sequential order of the ports. Several port scans were being conducted:

**Detection Query:**

```kql
let IPInQuestion = "10.1.0.140";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

## Sample Output:

<img width="1163" height="641" alt="Screenshot 2026-02-27 111034" src="https://github.com/user-attachments/assets/8a922166-3ce6-468c-ba19-d41eb07ded62" />

---

## Further Investigation

We pivoted to the DeviceProcessEvents table to observe if we could find anything suspicious around the time the port scan started. Noticed a powershell script named portscan.ps1 launching at 2026-02-27T18:09:29.6512222Z


**Detection Query:**
```kql
let VMname = "danscenariolab";
let specificTime = datetime(2026-02-27T18:10:01.3976938Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime))
| where DeviceName == VMname
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
## Sample Output:

<img width="1178" height="549" alt="Screenshot 2026-02-27 112108" src="https://github.com/user-attachments/assets/08889665-0409-480c-a84f-2386cb93c3ae" />

---

I observed the port scan script was launched by the dano12go account.

**Detection Query:**
```kql
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime))
| where DeviceName == VMname
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

## Sample Output:
<img width="1168" height="265" alt="Screenshot 2026-02-27 113627" src="https://github.com/user-attachments/assets/fe2940f6-5dce-41fc-ac56-3e6e57b2c338" />

---

**Relevant TTPs(Tactics, Techniques, and Procedures):**

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **Tactic**        | **TTP ID** | **TTP Name**                         | **Description**                                                                                  | **Detection Relevance**                                                                 |
|------------------|------------|--------------------------------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| Reconnaissance   | T1046      | Network Service Discovery            | Adversary scans ports/services to identify open ports and available services.                   | Sequential failed connection attempts indicate active port scanning behavior.           |
| Execution        | T1059.001  | Command and Scripting Interpreter: PowerShell | Use of PowerShell to execute malicious scripts or commands.                                       | Detection of `portscan.ps1` execution confirms scripted reconnaissance activity.        |
| Initial Access   | T1078      | Valid Accounts                       | Adversary uses legitimate credentials to execute malicious activity.                             | Port scan executed under `dan12go` account indicates potential account misuse.          |
| Command and Control | T1105   | Ingress Tool Transfer                | Tools/scripts transferred to target system for execution.                                         | Presence of `portscan.ps1` suggests a tool was introduced or staged on the host.        |
| Lateral Movement | T1021      | Remote Services                      | Use of network connections to interact with other systems.                                        | Repeated connection attempts to multiple hosts/ports may indicate lateral probing.      |

---
**📝 Response:**  

   - Isolate the device on Microsoft Defender for Endpoint

