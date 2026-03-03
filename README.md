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


---

The only successful remote/network logins in the last 7 days for 'dano12go' account (3 total):

**Detection Query:**

```kql
DeviceLogonEvents
| where DeviceName == "danscenario1lab"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize count()
```
## Sample Output:
<img width="686" height="252" alt="OnlysuccessfullogonME" src="https://github.com/user-attachments/assets/766913fe-b066-45c6-bec2-83052fa4d073" />

There were 0 failed logons from this account, indicating no brute force attempt taking place for this account. Unlikely this was a 1-time password guess.

**Detecion Query:**

```kql
DeviceLogonEvents
| where DeviceName == "danscenario1lab"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "dano12go"
| summarize count()
```
## Sample Output:
<img width="692" height="188" alt="0failedlogons" src="https://github.com/user-attachments/assets/92c00770-ad6c-4825-9349-aeecf4b7581a" />

---

We checked successful login IPs for "dano12go" to see if any of them were unusual or from an unexpected location. all were normal. The location for the remote IP in the screenshot is in the area I am at.

```kql
DeviceLogonEvents
| where DeviceName == "danscenario1lab"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "dano12go"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

## Sample Output:
<img width="685" height="229" alt="SuccessfulLogonCheck" src="https://github.com/user-attachments/assets/e013a47b-0743-41a3-b18f-3d9fd848e9bb" />

---

The device exposed to the internet has clear brute force attempts occuring. There is no evidence of any brute force success or unauthorized access from legitimate account "dano12go" 

---
Relevant TTPs(Tactics, Techniques, and Procedures):

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                      | **Description**                                                                                  | **Detection Relevance**                                                                 |
|------------|-----------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| T1190      | Exploit Public-Facing Application | System was publicly accessible, making it a potential target for exploitation attempts.          | Helps identify exposed services and potential attack surfaces from internet-facing apps.|
| T1110      | Brute Force                       | Multiple failed login attempts from external IPs indicate brute-force activity.                  | Detects repeated authentication failures, signaling credential-based attacks.           |
| T1078      | Valid Accounts (Attempted)        | Adversaries attempted to authenticate using legitimate credentials but were unsuccessful.        | Helps monitor for unauthorized use or attempted abuse of valid credentials.             |

---
**📝 Response:**  

   - Harden NSG of VM to allow only RDP from specific endpoints. ( no public internet access)
   - Enable MFA

