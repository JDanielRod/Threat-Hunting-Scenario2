# 🔍**Detection of Internet-facing sensitive assets**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ab796c31-b368-4294-af03-cae6f68f4f3f" />


## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet.

NOTE: I spun up a VM on Azure, and then onboarded it to Microsoft Defender for Endpoint. This will act as the internet-facing asset for this example.

## Goal:
Identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

---

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:**  danscenario1lab has been internet-facing for a day or so.
   
   - Last Internet facing time: `2025-01-06T19:15:05.9710276Z`
  
   - **Detection Query:**
```kql
DeviceInfo
| where DeviceName == "danscenario1lab"
| order by Timestamp desc
```

## Sample Output:

<img width="647" height="305" alt="image" src="https://github.com/user-attachments/assets/6919b9e0-1af3-4fe2-9477-a5064a0a61ed" />


---

### Brute Force Attempts Detection

A few bad actors have been discovered attempting to log into target machine (danscenario1lab)

**Detection Query:**

```kql
DeviceLogonEvents
| where DeviceName == "danscenario1lab"
| where LogonType has_any("Network", "Interactive","RemoteInteractive","Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

## Sample Output:

<img width="686" height="276" alt="Scenario1DeviceLogonEventsExpanded" src="https://github.com/user-attachments/assets/71581581-14a9-433c-b42a-65b33819b87b" />

NOTE: The VM had been running for a limited time up to this point, so the results from the query yielded 3 IPS. If the VM kept running, there would more than likely be more bad actors trying to gain access.
---

## Further Investigation

The 3 IPs that have attempted logins have not been able to gain access.

**Detection Query:**
```kql
let RemoteIPsInQuestion = dynamic(["185.156.73.74", "185.218.138.3", "185..156.73.169"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
## Sample Output:
<img width="689" height="365" alt="NoSuccessfulLogin" src="https://github.com/user-attachments/assets/0a025dac-31c6-442f-a203-39adc47e3bd7" />

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

