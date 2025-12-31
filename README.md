# Help-IT-s-Complicated-Investigation

## Objective

To perform a structured cybersecurity investigation by analyzing Windows event logs, identifying suspicious activity, and documenting findings using a clear SOC‑style workflow. This project demonstrates my ability to break down an incident, review relevant artifacts, interpret log data, and communicate results in a professional, repeatable format.

### Skills Learned
- Understanding how to approach an investigation using a SOC workflow
- Identifying key Windows Event Logs relevant to authentication, process creation, and security events
- Reviewing Windows Defender alerts and correlating them with system activity
- Recognizing indicators of suspicious behavior and validating them with log evidence
- Documenting findings clearly using structured reporting (What Happened, How It Was Detected, Impact, Recommendations)
- Mapping activity to MITRE ATT&CK techniques at a beginner‑friendly level
- Strengthening analytical thinking and evidence‑based decision making
- Improving familiarity with triage steps: verify, correlate, conclude

### Tools Used
- Windows Event Viewer – log review and event correlation
- Sysmon – process creation, network connection, and system activity visibility
- Windows Defender – alert review and threat detection context
- PowerShell – command‑line awareness and script interpretation
- CyberChef – decoding, parsing, and quick data analysis
- VirusTotal – file and hash reputation checks
- Notepad++ – note‑taking, log parsing, and documentation
- Splunk (Fundamentals) – understanding how SIEM searches and detection logic work

## Steps

# Findings

The investigation confirms a full compromise of BACKOFFICE‑PC1, including credential theft, data exfiltration, persistence creation, and Kerberos abuse. The attacker leveraged built‑in Windows tools to evade detection and maintained access for over 16 hours. Sensitive data and credentials were successfully exfiltrated to an external Discord webhook

**1. Compromise of the helpdesk account**

All malicious activity on BACKOFFICE‑PC1 was executed under the **helpdesk** user account, indicating the attacker had full access to this credential prior to the first observed event. PowerShell, certutil, curl, and other tools were launched under this identity.

**2. Malicious payloads downloaded using certutil**

The attacker used **certutil.exe**, a trusted Windows utility, to download multiple malicious executables from the external IP **64.226.121.55**. These included:

- `GoogleUpdateCore.exe`
- `msedge.exe` (Mimikatz)
- `Rubeus.exe`

All payloads were stored in suspicious directories such as **C:\Users\Public\Libraries** and **C:\ProgramData\Microsoft**.

**3. Execution of credential theft tools**

The attacker executed **Mimikatz** (disguised as msedge.exe) via PowerShell ScriptBlock logging. This resulted in:

- Extraction of credentials from LSASS
- Creation of **creds.txt** containing plaintext passwords and hashes
- Exfiltration of this file to a Discord webhook

This confirms successful credential compromise.

**4. Data staging and exfiltration**

The attacker used **robocopy** to stage likely HR and Patient data into:

- `C:\ProgramData\Microsoft\Backup\Staging\HR`
- `C:\ProgramData\Microsoft\Backup\Staging\Patients`

The data was then compressed into **KCD_Exfil.zip** and exfiltrated using **curl.exe** to the same Discord webhook used for credential theft.

**5. Persistence mechanisms established**

The attacker created a new domain account:

- **backup$** with password `verySecure123!`

Additionally, the attacker modified the Run key:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthSystray`

These actions indicate intent to maintain long‑term access.

**6. Kerberos abuse and weak encryption usage**

A Kerberos Ticket Granting Ticket (TGT) request for **James.Allen** was observed using:

- **RC4‑HMAC (0x17)** encryption

This is a weak and deprecated encryption type commonly targeted for **Kerberoasting** and offline password cracking.

**7. Repeated failed authentication attempts**

Logs show **15 failed login attempts** against **ADDC01**, indicating attempts to authenticate or brute‑force credentials during the attack window.

**8. Long‑duration connection to attacker infrastructure**

BACKOFFICE‑PC1 maintained outbound connections to **64.226.121.55** from:

- **3:07 AM** until **7:51 PM**

This confirms sustained command‑and‑control activity throughout the day

# Investigation Summary

The investigation determined that **`BACKOFFICE‑PC1`** was compromised on **2025‑11‑04**, with all malicious activity executed under the **`helpdesk**` user account. The attacker leveraged built‑in Windows tools such as **`certutil`**, **`PowerShell`**, **`robocopy`**, and **`curl**` to download malware, execute credential‑theft tools, stage sensitive data, and exfiltrate information to an external Discord webhook.

Initial activity began at **02:54 AM**, when `certutil` was used to download a malicious executable named **`GoogleUpdateCore.exe**` from the attacker’s server at **`64.226.121.55`**. This payload was stored and executed from the suspicious directory **`C:\Users\Public\Libraries`**, indicating deliberate evasion of standard security controls. Shortly after execution, the compromised host established outbound connections to the attacker’s IP over ports 8080 and 443.

Between **03:58 AM and 04:57 AM**, the attacker staged likely HR and Patient data using **`robocopy`**, compressed it into **`KCD_Exfil.zip`**, and exfiltrated it to a Discord webhook. During this same window, the attacker downloaded and executed **`Mimikatz**` (disguised as `*msedge.exe*`) to dump credentials into **`creds.txt`**, which was also exfiltrated externally.

The attacker then escalated persistence by creating a new domain account named **`backup$`** and modifying the **`SecurityHealthSystray`** Run key to maintain long‑term access. At **05:26 AM**, the attacker downloaded **`Rubeus.exe`**, a tool commonly used for Kerberos ticket manipulation. Later logs show a Kerberos Ticket Granting Ticket (TGT) request for the user **`James.Allen`** using the weak **RC4‑HMAC (0x17)** encryption type, consistent with Kerberoasting attempts.

Malicious activity continued throughout the morning, with the final observed connection to the attacker’s IP ending at **07:51 PM**, indicating the attacker maintained access for most of the day. No additional malicious activity was observed after this time, though persistence mechanisms and compromised credentials remain a risk.

Overall, the investigation confirms a **full kill‑chain compromise** involving initial access, execution, credential theft, data staging, exfiltration, persistence, and Kerberos abuse. Immediate containment and remediation actions are required to prevent further unauthorized access or data loss.

# Who

The attacker operated under the `helpdesk` account, compromised `James.Allen` Kerberos authentication, created a persistence account (`backup$`), and used `BACKOFFICE-PC1` as the primary attack platform while communicating with external IP `64.226.121.55` and exfiltrating data to a Discord webhook.

**1. Compromised / Misused Accounts**

These accounts were directly used during the attack:

- **BACKOFFICE-PC1\helpdesk**
    - Used to run PowerShell, certutil, curl, robocopy, and malicious binaries.
    - All malicious activity on the workstation occurred under this account.
    - Indicates the attacker had full access to this user’s credentials.
- **James.Allen**
    - A Kerberos Ticket Granting Ticket (TGT) was requested using **RC4-HMAC (0x17)**.
    - This suggests the attacker attempted Kerberoasting or offline cracking of this account.
- **backup$** *(malicious account created by attacker)*
    - Created using `net1.exe` with password `verySecure123!`.
    - Purpose: persistence and future unauthorized access.

**2. Affected Hosts**

These systems were directly involved in the attack:

- **BACKOFFICE-PC1**
    - Primary compromised workstation.
    - All malicious downloads, credential dumping, data staging, and exfiltration occurred here.
- **ADDC01**
    - Domain controller targeted with failed login attempts (15 failures).
    - Kerberos activity involving RC4-HMAC observed.

**3. Attacker Infrastructure**

The attacker used the following external resources:

- **Attacker IP:** `64.226.121.55`
    - Hosted malicious payloads (GoogleUpdateCore.exe, mimikatz.exe, Rubeus.exe).
    - Maintained long-running C2 connection until **7:51 PM**.
- **Discord Webhook**
    - Used for exfiltrating:
        - `creds.txt` (credential dump)
        - `KCD_Exfil.zip` (Likely HR & Patient data)

**4. Malicious Tools Used**

These tools confirm attacker identity and intent:

- **certutil.exe** (LOLBIN used for downloading payloads)
- **PowerShell** (execution of Mimikatz and exfiltration commands)
- **GoogleUpdateCore.exe** (malicious payload)
- **msedge.exe** (Mimikatz disguised)
- **Rubeus.exe** (Kerberos abuse tool)
- **curl.exe** (exfiltration to Discord)
- **robocopy.exe** (data staging)
- **mimikatz.exe** (credential theft)

# What

On 2025-11-04 2:54 UTC The attacker operated under the `helpdesk` account, indicating user `helpdesk` was likely compromise. Attacker use legitimate Windows tool `certutil.exe` to download `GoogleUpdateCore.exe` to execute script to still information and to export data. 

On 2025-11-04 03:01 UTC attacker downloaded a executable called `GoogleUpdateCore.exe` on `BACKOFFICE-PC1`. A network connection from `172.16.0.109` (printer subnet) to the attacker’s IP was observed. 

Attacker used certutil.exe to down `GoogleUpdateCore.exe` which is stored in the directory `C:\Users\Public\Libraries\`. This directory is suspicious as it not a directory frequently used by any user or legitimate files. This is a know location usually used by hacker. 

On 2025-11-04 3:07 - 3:12 UTC network connection established to attacker IP `64.226.121.55`

On 2025-11-04 3:20 UTC attack used discovery command `whoami` to find more information on user and the network. The `whoami` command is usually used by attacker for situational awareness and post exploitation reconnaissance to assess current access level within the compromised system. 

On 2025-11-04 3:58 UTC Attacker also used command robocopy to data to directory `C:\ProgramData\Microsoft\Backup\Staging\HR`.

On 2025-11-04 3:58 - 2025-11-05 18:42 UTC attacker tried to login to account `ADD01` but failed 16 attempts due to pad password.  

On 2025-11-04 4:08 UTC attacker disguise malicious tool called `msedge.exe` which is `mimikatz.exe`. Mimikatz is a known hacking tool use to gather exploit network and vary other malicious attacks.

On 2025-11-04 4:09 UTC attacker use `msedge.exe` to steal credentials and saved on file called `creds.txt`. 

On 2025-11-04 4:24 UTC attacker exported the `creds.txt` to a discord server link `https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8`

On 2025-11-04 4:55 UTC attacker used PowerShell to accessed staging directory for exfiltration. 

On 2025-11-04 4:57 attacker extract data from the network and compile into zip file located in `C:\ProgramData\Microsoft\Backup\KCD_Exfil.zip`. This zip file was also exported to discord server link `https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8`

On 2025-11-04 5:10 UTC attacker create new user `backup$` to maintain access to the network. The remote command use was `C:\Windows\system32\net1 user /add backup$ verySecure123! /domain` using `net1.exe`. `Net1.exe` is an older alternative version to net.exe to fix Y2K issue and `net.exe` will use net1.exe for certain tasks this is due to backward compatibility within Windows. 

On 2025-11-04 5:16 UTC attacker used the malicious msedge.exe to attack 15 other service accounts. Checking the log for event ID 4769 which is Kerberos service ticket request these 15 accounts was logged requesting service ticket. The attacker modified `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthSystray` to maintain persistence.

On 2025-11-04 5:26 UTC attacker downloaded malicious tool `Rubeus.exe` in to directory  `C:\ProgramData\Microsoft\`  to look like legitimate program. `Rubeus.exe` is commonly used to attack Kerberos authentication to gather user hashes and other tools are used to crack that hash which us usually the password to different users.

On 2025-11-04 6:40 UTC attacker used malicious tool `msedge.exe` to extract domain user password of `james.allen`.

On 2025-11-04 7:09 UTC during the Kerberos attack the attacker utilize and older encryption type RC4-HMAC. The attacker requested authentication ticket from Kerberos to send in older encryption so attacker can crack the vulnerable encryption offline 

On 2025-11-04 7:51 UTC attacker IP `64.226.121.55` network connect ended and last seen on logs. 

# When

**Start:** 2025‑11‑04 02:54 AM UTC First malicious activity: certutil download of `GoogleUpdateCore.exe`

**Key activity window:** 02:54 AM – 07:09 AM UTC Credential dumping, data staging, exfiltration, persistence

**End:** 2025‑11‑04 07:51 PM UTC Network connection to attacker IP ended

**Current status:** No further malicious activity observed after 07:51 PM. Attack appears **contained**, but persistence mechanisms were installed and require remediation.

# Where

**Affected systems:**

- **BACKOFFICE-PC1** (primary compromised workstation)
- **ADDC01** (domain controller targeted for authentication attempts)

**Affected accounts:**

- `BACKOFFICE-PC1\helpdesk` (used to execute malicious commands)
- `James.Allen` (Kerberos ticket requested with RC4-HMAC)
- `backup$` (malicious persistence account created)

**Network locations:**

- **Attacker IP:** 64.226.121.55 (ports 8080 and 443)
- **Internal IP involved:** 172.16.0.109 (printer subnet)
- **Data staging directory:**`C:\ProgramData\Microsoft\Backup\Staging\`
- **Malware storage directory:**`C:\Users\Public\Libraries\`

# Why

**Primary motives:**

- **Credential theft**
(Mimikatz → creds.txt → exfil to Discord)
- **Data theft**
(HR and Patient data staged → zipped → exfil to Discord)
- **Persistence**
(backup$ account, Run key modification)
- **Kerberos abuse**
(RC4-HMAC ticket request for offline cracking)

**Root cause (if known):**

- The helpdesk account was used to run all malicious commands, indicating **credential compromise** prior to the first log entry

# How

**Initial access method:**

- Compromised helpdesk credentials used to run PowerShell and certutil.

**Execution:**

- Downloaded and executed malicious binaries (`GoogleUpdateCore.exe`, `msedge.exe`, `Rubeus.exe`).

**Privilege escalation & credential access:**

- Mimikatz executed via PowerShell ScriptBlock.

**Lateral movement preparation:**

- Kerberos RC4-HMAC ticket requested.

**Data staging & exfiltration:**

- robocopy → staging folder
- Compress-Archive → KCD_Exfil.zip
- curl → Discord webhook

**Persistence:**

- Created domain account `backup$`
- Modified Run key for auto-star

# Recommendations:

**1. Immediately isolate BACKOFFICE-PC1**

- Remove the system from the network to prevent further command‑and‑control communication, credential theft, or exfiltration.
- This host executed all malicious binaries and should be treated as fully compromised.

**2. Disable and reset all compromised accounts**

- **Disable the helpdesk account** until its credentials are reset and re‑issued.
- **Reset the password for James.Allen**, as Kerberos tickets were requested using weak RC4‑HMAC encryption.
- **Remove the malicious persistence account `backup$`** and audit for any other unauthorized accounts.

**3. Revoke Kerberos tickets and force re‑authentication**

- Perform a **Kerberos purge** (klist purge) on affected systems.
- Force a **domain‑wide password reset** for service accounts if any were targeted.
- Ensure **AES encryption types** are enforced; disable RC4‑HMAC (0x17) if possible.

**4. Remove persistence mechanisms**

- Delete the malicious Run key:`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthSystray`
- Search for additional autoruns, scheduled tasks, or startup items created during the attack window.

**5. Block attacker infrastructure**

- Block outbound traffic to:**64.226.121.55** (ports 8080 and 443)
- Block outbound connections to **Discord webhook domains** to prevent future exfiltration.

**6. Quarantine and remove malicious binaries**

Delete the following from all systems where found:

- `GoogleUpdateCore.exe`
- `msedge.exe` (Mimikatz)
- `Rubeus.exe`
- Any files in:`C:\Users\Public\Libraries\C:\ProgramData\Microsoft\Backup\Staging\`

**7. Conduct a full credential hygiene reset**

Because Mimikatz was executed:

- Reset **all passwords** for users logged in during the compromise window.
- Reset **local administrator passwords**.
- Rotate **service account passwords**.
- Invalidate cached credentials.

**8. Review and harden PowerShell and certutil usage**

- Enable **Constrained Language Mode** for non‑admin users.
- Enable **PowerShell ScriptBlock Logging** and **Module Logging**.
- Restrict or monitor use of **certutil.exe**, **curl.exe**, and **robocopy.exe**.

**9. Improve monitoring and detection**

Deploy or tune alerts for:

- certutil downloads
- PowerShell invoking external binaries
- Execution from `C:\Users\Public\Libraries\`
- RC4‑HMAC Kerberos ticket requests
- Outbound connections to unusual IPs
- Discord webhook exfiltration patterns
- Mimikatz/Rubeus signatures

**10. Perform a full forensic review**

- Analyze LSASS memory for additional credential exposure.
- Review domain controller logs for lateral movement attempts.
- Examine network logs for additional exfiltration channels

# Evidences:

Network connection from external IP 
<img width="1093" height="1568" alt="image" src="https://github.com/user-attachments/assets/e7ee7a7a-9fd0-4106-a834-0910897abbd3" />

helpdesk user loaded malicious googleupdatecore.exe
<img width="1089" height="1069" alt="image" src="https://github.com/user-attachments/assets/67ab36bb-f95d-4826-a1b4-10dd549412bb" />

attacker utlized certutil.exe to download file
<img width="1100" height="679" alt="image" src="https://github.com/user-attachments/assets/442e9473-b82e-4a21-8da8-b67611783a4f" />
<img width="1080" height="539" alt="image" src="https://github.com/user-attachments/assets/2b77227d-b6d1-4cf7-b079-e6b0d02d73f1" />

attacker download malicious msedge.exe
<img width="1095" height="939" alt="image" src="https://github.com/user-attachments/assets/c6d4fb04-674f-4bd8-a5af-5c8d4a18d122" />

attacker used rubeus.exe 
<img width="1105" height="956" alt="image" src="https://github.com/user-attachments/assets/155b541b-138e-47e8-9ccf-8be2d1c8d212" />

attacker used msedge.exe to gather logins
<img width="1096" height="555" alt="image" src="https://github.com/user-attachments/assets/d176e788-504e-4b63-873c-84836bfe77c7" />

attacker obtain plaint text password of user account
<img width="1102" height="975" alt="image" src="https://github.com/user-attachments/assets/1d48ee35-0c1c-44bb-97da-53a2fe626d51" />

Logs show account users tried to attack
<img width="1105" height="636" alt="image" src="https://github.com/user-attachments/assets/0b40b621-118b-43d1-b991-f5e68ec162df" />

attacker ran whomai command
<img width="1088" height="899" alt="image" src="https://github.com/user-attachments/assets/a1147275-219b-4274-b237-25a12a8ad7fd" />

attacker create file with credentials 
<img width="1103" height="1523" alt="image" src="https://github.com/user-attachments/assets/c71c96b0-c4f6-450a-b333-e012106805e8" />

attacker exported files to discord
<img width="1104" height="1026" alt="image" src="https://github.com/user-attachments/assets/ebb5add8-7af0-4178-916f-3334e8ae05e8" />

attacker exported zip file to discord
<img width="1113" height="1018" alt="image" src="https://github.com/user-attachments/assets/2f9a67dc-2c42-4a16-bb46-79c945ceb504" />

logs show failed login attemps
<img width="1104" height="976" alt="image" src="https://github.com/user-attachments/assets/d4e36fdb-428f-4d22-9f4b-250500ce1052" />

log show attacker copied and stage in certain directory
<img width="1090" height="286" alt="image" src="https://github.com/user-attachments/assets/d35443e7-e172-4fbb-b911-60feca257be5" />

logs show new account created with password
<img width="1088" height="1360" alt="image" src="https://github.com/user-attachments/assets/1c8758c3-a202-43c7-82f4-ca1d1e98fc04" />

log show attacker used vulnerable encryption
<img width="1093" height="1399" alt="image" src="https://github.com/user-attachments/assets/1b9c4d44-3f49-4bd9-8bbc-1fc54871a054" />

kerberos encryption types
<img width="1052" height="603" alt="image" src="https://github.com/user-attachments/assets/2efb3912-3f22-412c-ad37-1f3dbac1c317" />







