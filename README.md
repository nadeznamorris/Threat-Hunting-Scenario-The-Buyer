# Threat-Hunt-Scenario-The-Buyer

## RDP Compromise Incident

**Report ID:** INC-2026-1403

**Analyst:** Nadezna Morris

**Date:** 14-March-2026

**Incident Date:** 27-January-2026

---

## Executive Summary

Following the initial compromise documented in ***The Broker***, a ransomware affiliate leveraged pre-staged persistent access to re-enter the Ashford Sterling environment and deploy Akira ransomware. The threat actor operated with clear deliberateness: access had been planted during the prior intrusion and was reactivated in this campaign.
The attacker disabled security tooling, harvested credentials from LSASS, performed internal network reconnaissance, exfiltrated sensitive data, and ultimately encrypted files across two systems — AS-SRV and AS-PC2 — before dropping a ransom note and self-cleaning the environment. Encryption commenced at **22:18:33**. A ransom demand of **£65,000** was issued via a TOR-hosted Akira negotiation portal.

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Indicator                                                      | Description                                         |
| -------------------------------------------------------------- | --------------------------------------------------- |
| 88.97.164.155                                                  | Attacker external IP address                        |
| david.mitchell                                                 | Compromised domain user — primary attacker foothold |
| as.srv.administrator                                           | Lateral movement account used to access AS-SRV      |
| kill.bat                                                       | Security control termination script                 |
| st.exe                                                         | Data staging / compression tool                     |
| updater.exe                                                    | Akira ransomware binary (masqueraded)               |
| sync.cloud-endpoint.net                                        | Tool download staging server                        |
| cdn.cloud-endpoint.net                                         | C2 beacon communications                            |
| relay-0b975d23.net.anydesk.com                                 | AnyDesk relay server                                |
| akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion | Akira negotiation portal                            |
| HKLM\SOFTWARE\Policies\Microsoft\Windows Defender              | Windows Defender disabled at 21:03:42               |

---

### **KQL Queries Used:**

***SECTION 1: RANSOM NOTE ANALYSIS***

<img width="636" height="657" alt="Ransomware note" src="https://github.com/user-attachments/assets/25e0905f-d491-4cb5-9307-e0c103e572ad" /> <br>

**Objective:** Identify the ransomware group from the ransom note.  
**Flag:** `Akira`

**Objective:** The ransom note provides a contact method.  
**Flag:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

**Objective:** Each victim receives a unique identifier for negotiations.  
**Flag:** `813R-QWJM-XKIJ`

**Objective:** Each victim receives a unique identifier for negotiations.  
**Flag:** `.akira`

---

***SECTION 2: INFRASTRUCTURE***

**Objective:** Each victim receives a unique identifier for negotiations. 

**Flag:** `sync.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="1257" height="91" alt="image" src="https://github.com/user-attachments/assets/f77288a5-4897-4177-95b9-3602078db329" /> <br>

**Objective:** The payload established outbound connections.

**Flag:** `cdn.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName == ("as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="1213" height="116" alt="image" src="https://github.com/user-attachments/assets/81dbfb62-204b-40dc-90e2-e94453a2c527" /> <br>

**Objective:** The C2 infrastructure resolved to multiple IPs.

**Flag:** `104.21.30.237, 172.67.174.46`

```
DeviceNetworkEvents
| where DeviceName =="as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteUrl has_any ("sync.cloud-endpoint.net", "cdn.cloud-endpoint.net")
| distinct DeviceName, RemoteIP
```
<img width="275" height="107" alt="image" src="https://github.com/user-attachments/assets/6416fbab-80ba-4e5f-a584-0321ffa849b8" /> <br>

**Objective:** A Remote Tool route through relay servers.

**Flag:** `relay-0b975d23.net.anydesk.com`

```
DeviceNetworkEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteUrl has_any ("relay", "tunnel", "proxy", "gateway", "remote", "connect", "access")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated desc
```
<img width="955" height="68" alt="image" src="https://github.com/user-attachments/assets/02f86e8e-8868-4c33-a6d7-75a4411a42b2" />

---

***SECTION 3: DEFENSE EVASION***

**Objective:** A script was used to disable security controls.

**Flag:** `kill.bat`

```
DeviceFileEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any (".ps1", ".bat", ".cmd")
| where FileName !startswith "__PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="1130" height="80" alt="image" src="https://github.com/user-attachments/assets/03790339-3bf5-4025-89ae-128191b3fe44" /> <br>

**Objective:** Identify the hash of the evasion script.

**Flag:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

```
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any (".ps1", ".bat", ".cmd")
| where FileName !startswith "__PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated desc
```
<img width="1299" height="85" alt="image" src="https://github.com/user-attachments/assets/cd6f24f1-c9c8-4f93-ae2e-127a2a6d3008" /> <br>

**Objective:** Windows Defender was disabled via registry modification.

**Flag:** `DisableAntiSpyware`

```
DeviceRegistryEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RegistryKey has "Windows Defender"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated desc 
```
<img width="1142" height="82" alt="image" src="https://github.com/user-attachments/assets/c98eae49-1688-4d90-9768-b0d506d54dfc" /> <br>

**Objective:** Determine when the registry was modified.

**Flag:** `21:03:42`

```
DeviceRegistryEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RegistryKey has "Windows Defender"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated desc 
```
<img width="1142" height="82" alt="image" src="https://github.com/user-attachments/assets/c98eae49-1688-4d90-9768-b0d506d54dfc" />

---

***SECTION 4: CREDENTIAL ACCESS***

**Objective:** The attacker enumerated running processes to locate a target for credential theft.

**Flag:** `tasklist | findstr lsass`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ProcessCommandLine has_any ("tasklist","Get-Process","wmic process","ps")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="768" height="73" alt="image" src="https://github.com/user-attachments/assets/d0fd6213-23d4-42b2-aa37-e9cc0697d149" /> <br>

**Objective:** A named pipe was accessed during credential theft activity.

**Flag:** `\Device\NamedPipe\lsass`

```
DeviceEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, PipeName
| sort by TimeGenerated asc
```
<img width="643" height="106" alt="image" src="https://github.com/user-attachments/assets/b913959f-104d-4e25-9143-d10d8b3e4d74" /> <br>

---

***SECTION 5: INITIAL ACCESS***

**Objective:** A remote access tool was pre-staged from the previous attack.

**Flag:** `Anydesk.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("anydesk.exe", "teamviewer.exe", "ngrok.exe", "cloudflared.exe", "rutserv.exe", "radmin.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="790" height="72" alt="image" src="https://github.com/user-attachments/assets/9557eaf7-33a8-4f21-b223-ba5dbecb817f" /> <br>

**Objective:** The remote access tool was running from an unusual location on AS-PC2.

**Flag:** `C:\Users\Public\`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("anydesk.exe", "teamviewer.exe", "ngrok.exe", "cloudflared.exe", "rutserv.exe", "radmin.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="817" height="71" alt="image" src="https://github.com/user-attachments/assets/3a51e0fe-8dae-4413-9786-5b6674e065f7" /> <br>

**Objective:** Identify the attacker's external IP address.

**Flag:** `88.97.164.155`

```
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteIPType == "Public"
| where InitiatingProcessCommandLine has_any ("Anydesk")
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| sort by TimeGenerated asc
```
<img width="757" height="73" alt="image" src="https://github.com/user-attachments/assets/082fbcfe-3d86-45ff-b08e-28498da31ff9" /> <br>

**Objective:** Identify the user account that was compromised.

**Flag:** `david.mitchell`

```
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteIPType == "Public"
| where InitiatingProcessCommandLine has_any ("Anydesk")
| where RemotePort == 7070
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| sort by TimeGenerated asc
```
<img width="900" height="75" alt="image" src="https://github.com/user-attachments/assets/d38af04c-86bf-4e1d-b4a8-c4ef93260962" />

---

***SECTION 6: COMMAND & CONTROL***

**Objective:** A pre-staged beacon from The Broker failed to maintain stable communications. A new beacon was deployed.

**Flag:** `wsync.exe`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where InitiatingProcessFileName has_any ("wsync.exe", "powershell.exe", "cmd.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="772" height="81" alt="image" src="https://github.com/user-attachments/assets/908faeed-bccb-4fd8-900f-6576d5529214" /> <br>

**Objective:** Identify where the beacon was deployed.

**Flag:** `c:\programdata\`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName == "wsync.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="750" height="102" alt="Flag 20" src="https://github.com/user-attachments/assets/45b6f57a-0a63-4a53-a63c-838b9eedcb14" /> <br>

**Objective:** Identify the hash of the C2 beacon.  

**Flag:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName == "wsync.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="960" height="70" alt="image" src="https://github.com/user-attachments/assets/46dae70b-fc1d-4581-ac4e-27aba05e7026" /> <br>

**Objective:** A new beacon was deployed to replace the failed one.

**Flag:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName == "wsync.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```
<img width="1147" height="113" alt="image" src="https://github.com/user-attachments/assets/aef40fd6-ac2e-475b-938e-5caae0881fe8" />

---

***SECTION 7: RECONNAISSANCE***

**Objective:** A network scanner was deployed.

**Flag:** `"scan.exe"`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("scan")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="975" height="81" alt="image" src="https://github.com/user-attachments/assets/ba47d66e-5737-40d6-ab11-3ba757d5e481" /> <br>

**Objective:** Identify the hash of the scanner.

**Flag:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("scan")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```
<img width="1195" height="83" alt="image" src="https://github.com/user-attachments/assets/62850757-a86c-4107-b016-86484a9e9082" /> <br>

**Objective:** The network scanner was executed with specific arguments revealing the attacker's intent.

**Flag:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where AccountName == "david.mitchell"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by TimeGenerated desc
```
<img width="1292" height="90" alt="image" src="https://github.com/user-attachments/assets/cf34fb6d-c4c8-4e8f-ab66-599630d8c3ae" /> <br>

**Objective:** The attacker enumerated network shares on specific hosts.

**Flag:** `10.1.0.183, 10.1.0.154`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("view")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="680" height="95" alt="image" src="https://github.com/user-attachments/assets/acf7966f-4fc6-423d-a9ce-4a794ba74865" />

---

***SECTION 8: LATERAL MOVEMENT***

**Objective:** An account was used to access AS-SRV.

**Flag:** `as.srv.administrator`

```
DeviceLogonEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| project TimeGenerated, DeviceName, AccountName, AccountDomain, LogonType
| order by TimeGenerated asc
```
<img width="720" height="70" alt="image" src="https://github.com/user-attachments/assets/0e5d4a61-9e91-4c1d-9a42-96ef76438918" />

---

***SECTION 9: TOOL TRANSFER***

**Objective:** A living-off-the-land binary was used first but had issues.

**Flag:** `bitsadmin.exe`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName in~ (
    "certutil.exe", "bitsadmin.exe", "powershell.exe", 
    "mshta.exe", "wscript.exe", "cscript.exe", 
    "curl.exe", "wget.exe", "regsvr32.exe", "rundll32.exe"
)
| where ProcessCommandLine has_any ("http", "ftp", "download", "urlcache", "transfer")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="780" height="95" alt="image" src="https://github.com/user-attachments/assets/4e38acfa-5d82-4357-908b-d324cd486547" /> <br>

**Objective:** After the first tool failed, another method was used.

**Flag:** `Invoke-WebRequest`

```
DeviceEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "PowerShellCommand"
| project TimeGenerated, DeviceName, AdditionalFields, AccountName
| order by TimeGenerated asc
```
<img width="1456" height="112" alt="image" src="https://github.com/user-attachments/assets/e09ec3ab-0b8e-40c3-a7ac-80d3792207fc" />

---

***SECTION 10: EXFILTRATION***

**Objective:** A tool was used to compress data for exfiltration.

**Flag:** `st.exe`

```
DeviceProcessEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where AccountName != "system"
| where ProcessCommandLine has_any ("compress", ".zip", ".rar", ".7z", ".tar", "makecab", ".exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="766" height="75" alt="image" src="https://github.com/user-attachments/assets/f253bb0a-2c5b-499a-ad02-434a7d2e2099" /> <br>

**Objective:** Identify the hash of the staging tool.

**Flag:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

```
DeviceProcessEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where AccountName != "system"
| where ProcessCommandLine has_any ("compress", ".zip", ".rar", ".7z", ".tar", "makecab", ".exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```
<img width="1162" height="86" alt="image" src="https://github.com/user-attachments/assets/498064cf-8577-49b2-96aa-3655da43e593" /> <br?

**Objective:** Identify the archive created for exfiltration.

**Flag:** `exfil_data.zip`

```
DeviceFileEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz", ".cab")
| where ActionType == "FileCreated"
| where InitiatingProcessFileName == "st.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="952" height="78" alt="image" src="https://github.com/user-attachments/assets/936ea6d7-70aa-4e5c-a9d0-e488cd6a0099" />

---

***SECTION 11: RANSOMWARE DEPLOYMENT***

**Objective:** The ransomware was disguised as a legitimate process.  

**Flag:** `updater.exe`

```
DeviceProcessEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName endswith ".exe"
| where AccountName != "system"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="955" height="75" alt="image" src="https://github.com/user-attachments/assets/426fbd60-2057-4f3d-b266-916744c5e6ab" /> <br>

**Objective:** Identify the hash of the ransomware.

**Flag:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

```
DeviceProcessEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName endswith ".exe"
| where AccountName != "system"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256 
| order by TimeGenerated asc
```
<img width="1261" height="87" alt="image" src="https://github.com/user-attachments/assets/32647486-2f9e-49dc-9dae-373870ea5360" /> <br>

**Objective:** The ransomware was dropped onto AS-SRV before execution.

**Flag:** `powershell.exe`

```
DeviceFileEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName =~ "updater.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="950" height="74" alt="image" src="https://github.com/user-attachments/assets/8e582c4a-0e08-4110-8e21-ef0b2f8d49cc" /> <br>

**Objective:** The attacker deleted backup copies to prevent file recovery.

**Flag:** `vssadmin delete shadows /all /quiet`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ProcessCommandLine has_any (
    "vssadmin", "wbadmin", "bcdedit", 
    "shadowcopy", "delete shadows", "resize shadowstorage"
)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="867" height="92" alt="image" src="https://github.com/user-attachments/assets/aa279904-e239-4e5f-9156-f971f945f020" /> <br>

**Objective:** A ransom note was dropped after encryption began.

**Flag:** `updater.exe`

```
DeviceFileEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("readme", "ransom", "decrypt", "restore", "how_to", "recovery", "note")
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="1315" height="106" alt="image" src="https://github.com/user-attachments/assets/dfd93884-5e20-4566-abb4-b598f1d6ca87" /> <br>

**Objective:** Determine when encryption began.

**Flag:** `22:18:33`

```
DeviceFileEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("readme", "ransom", "decrypt", "restore", "how_to", "recovery", "note")
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="1277" height="143" alt="image" src="https://github.com/user-attachments/assets/b246b7f5-7e18-4535-9d1e-93f9b6711b86" />

---

***SECTION 12: ANTI-FORENSICS & SCOPE***

**Objective:** The ransomware binary was deleted after execution.

**Flag:** `clean.bat`

```
DeviceFileEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName =~ "updater.exe"
| where ActionType == "FileDeleted"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="1165" height="83" alt="image" src="https://github.com/user-attachments/assets/dd4bc704-af43-4f6d-a8b6-3df5c8ec3fa4" /> <br>

**Objective:** Determine the scope of the compromise.

**Flag:** `as-srv, as-pc2`

```
DeviceFileEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where InitiatingProcessFileName =~ "updater.exe"
| where ActionType == "FileCreated"
| summarize by TimeGenerated, DeviceName
```
<img width="357" height="106" alt="image" src="https://github.com/user-attachments/assets/21d96ad0-ee2e-4f0f-b7c6-9f14f5bfec66" />

---

## 2. Investigation Summary — Ashford Sterling Recruitment

**Phase 1 — Re-entry via Pre-Staged Access**  
The threat actor did not need to re-compromise the environment. **AnyDesk.exe**, planted during ***The Broker*** intrusion, was residing in `C:\Users\Public\` on AS-PC2 — an unusual and suspicious path for a remote access tool. The compromised account **david.mitchell** provided the initial foothold, with connections originating from the attacker's external IP `88.97.164.155`.
The pre-staged C2 beacon (`wsync.exe`) was initially reactivated but failed to maintain stable communications. The attacker promptly deployed a replacement beacon to `C:\ProgramData\` and re-established reliable C2 connectivity through `cdn.cloud-endpoint.net`, resolving to `104.21.30.237` and `172.67.174.46`. AnyDesk traffic was relayed through `relay-0b975d23.net.anydesk.com`.

**Phase 2 — Defence Evasion**  
Before any significant activity, the attacker moved to blind the environment's defences. At **21:03:42**, the Windows registry was modified — setting `DisableAntiSpyware` to disable Windows Defender. A batch script, **kill.bat**, was executed to terminate additional security processes and controls. With defensive tooling neutralised, the attacker had a clear runway for the remainder of the operation.

**Phase 3 — Credential Harvesting**  
The attacker enumerated running processes via `tasklist | findstr lsass` to locate the LSASS process, then accessed the named pipe `\Device\NamedPipe\lsass` to perform credential theft. Credentials harvested here — likely the **as.srv.administrator** account — enabled subsequent lateral movement to AS-SRV.

**Phase 4 — Reconnaissance and Lateral Movement**  
A portable network scanner, **scan.exe**, was executed from `C:/Users/david.mitchell/Downloads/` with the `/portable` and `/lng en_us` flags. The attacker targeted hosts `10.1.0.183` and `10.1.0.154`, enumerating available network shares. Using the **as.srv.administrator** account, the attacker successfully accessed AS-SRV, expanding their footprint to the server.

**Phase 5 — Tool Staging and Payload Download**  
With AS-SRV accessible, the attacker staged tools for the final phases. An initial attempt to download payloads using **bitsadmin.exe** (a living-off-the-land binary) encountered issues. The attacker pivoted to **Invoke-WebRequest** (PowerShell) as a fallback, successfully pulling tools from `sync.cloud-endpoint.net`.

**Phase 6 — Data Exfiltration**  
Prior to encryption, the attacker used **st.exe** to compress targeted data into an archive named **exfil_data.zip**. This archive was exfiltrated externally, providing the threat actor with the leverage required for their double-extortion model. Exfiltrated data reportedly included financial records, employee PII, client databases, contracts, internal communications, and proprietary business data.

**Phase 7 — Ransomware Deployment and Execution**  
The Akira ransomware binary was disguised as **updater.exe** and dropped onto AS-SRV via powershell.exe. Before triggering encryption, the attacker deleted all Volume Shadow Copies via:
`vssadmin delete shadows /all /quiet`
This command eliminated the primary native recovery mechanism. Encryption began at 22:18:33. The ransom note was written to disk by updater.exe. Following execution, the ransomware binary was deleted using clean.bat, removing the primary on-disk evidence of the payload.

**Phase 8 — Negotiation**  
Contact was made through the Akira TOR portal. The initial demand of £65,000 was met with a counter-offer of £11,000 from Ashford Sterling, citing their size as a small recruitment firm. Akira declined and issued a 48-hour deadline.

---

## 3. MITRE ATT&CK Mapping


| Tactic                    | Technique                                            | Evidence                                              |
| ------------------------- | ---------------------------------------------------- | ----------------------------------------------------- |
| Initial Access            | T1078 — Valid Accounts                               | david.mitchell account compromised                    |
| Persistence               | T1547 — Pre-staged Access                            | AnyDesk.exe in C:\Users\Public\                       |
| Command & Control         | T1219 — Remote Access Software                       | AnyDesk via relay-0b975d23.net.anydesk.com            |
| Command & Control         | T1071 — Application Layer Protocol                   | C2 beacon via cdn.cloud-endpoint.net                  |
| Defence Evasion           | T1562.001 — Impair Defences: Disable or Modify Tools | kill.bat; DisableAntiSpyware registry key             |
| Defence Evasion           | T1070 — Indicator Removal                            | clean.bat deletes ransomware binary post-execution    | 
| Credential Access         | T1003.001 — OS Credential Dumping: LSASS Memory      | LSASS named pipe access                               | 
| Discovery                 | T1057 — Process Discovery                            | tasklist | findstr lsass                              | 
| Discovery                 | T1135 — Network Share Discovery                      | scan.exe targeting 10.1.0.183, 10.1.0.154             | 
| Lateral Movement          | T1078 — Valid Accounts                               | as.srv.administrator used to access AS-SRV            |
| Resource Development      | T1608 — Stage Capabilities                           | Tools staged from sync.cloud-endpoint.net             |
| Command & Control         | T1197 — BITS Jobs (failed)                           | bitsadmin.exe attempted                               |
| Execution                 | T1059.001 — PowerShell                               | Invoke-WebRequest; payload dropped via powershell.exe |
| Collection / Exfiltration | T1560 — Archive Collected Data                       | st.exe creates exfil_data.zip                         |
| Impact                    | T1490 — Inhibit System Recovery                      | vssadmin delete shadows /all /quiet                   | 
| Impact                    | T1486 — Data Encrypted for Impact                    | Akira ransomware; .akira extension                    | 
| Exfiltration              | T1567 — Exfiltration Over Web Service                | Data exfiltrated prior to encryption                  |

---

## 4. Recommendations

### Immediate Actions

- Isolate AS-SRV and AS-PC2 from the network if not already done.
- Reset credentials for david.mitchell, as.srv.administrator, and all domain admin accounts.
- Block all IOC domains and IPs at the perimeter firewall and DNS layer.
- Preserve all available forensic artefacts before any remediation activity.

### Short-Term Remediation

- Rebuild AS-SRV and AS-PC2 from clean, verified images — do not trust in-place recovery.
- Audit all user accounts for signs of compromise or privilege escalation.
- Review AnyDesk and any other remote access tools across the environment; remove any not explicitly authorised.
- Audit C:\Users\Public\ and C:\ProgramData\ across all endpoints for unexpected executables.
- Re-enable and verify Windows Defender across all hosts; validate registry integrity.
- Re-establish Volume Shadow Copy services and verified backup integrity.

### Longer-Term Hardening

- Enforce application allowlisting to prevent execution of unsigned or unexpected binaries.
- Implement privileged access workstations (PAWs) and tiered admin models to prevent credential reuse across workstations and servers.
- Deploy a SIEM with alerting on LSASS access, shadow copy deletion, and registry modification to Defender keys.
- Enforce MFA on all remote access pathways, including any residual remote management tooling.
- Conduct a full review of the initial The Broker incident to identify and close all remaining persistence mechanisms beyond those documented here.
- Engage legal counsel and consider ICO notification obligations given the confirmed exfiltration of employee PII and client data.

---

**Report Status:** Complete  

**Next Review:** 21 March 2026  

**Distribution:** Cyber Range
