SOC Analyst Home Lab: Windows Security Monitoring & Incident Investigation
1. Project Overview

This project demonstrates a foundational Security Operations Center (SOC) monitoring workflow. It simulates a multi-stage security incident in a controlled lab environment, spanning a brute-force attempt, successful authentication, and local account persistence, using Splunk Enterprise and a Windows 11 virtual machine endpoint.

Note: All activity in this repository was performed in an isolated lab for learning purposes.

2. Lab Architecture and Environment
SIEM Host: Splunk Enterprise (receiving enabled, listening on TCP port 9997)
Victim Endpoint: Windows 11 Virtual Machine (VMware Workstation)
Agent: Splunk Universal Forwarder
Log Source: Windows Security Event Log (WinEventLog://Security)
Dedicated Index: wineventlog (created in Splunk under Settings > Indexes)
text
[Windows 11 VM (Victim)]
       |  Security Events: 4625 -> 4624 -> 4720 -> 4732
       v  Splunk Universal Forwarder (TCP 9997)
[Splunk Enterprise (SIEM Host) - Index: wineventlog]
3. Repository Structure
text
SOC-Analyst-HomeLab/
├── README.md
├── screenshots/
│   ├── 4625_brute_force.png
│   ├── 4720_user_creation.png
│   └── 4732_group_modification.png
├── configs/
│   ├── inputs.conf
│   └── outputs.conf
├── spl/
│   ├── brute_force_detection.spl
│   ├── account_creation.spl
│   └── attack_chain_correlation.spl
└── reports/
    └── incident_report.md
4. Implementation and Setup Steps
Step 1: Splunk Index and Receiver

On Splunk Enterprise:

Create the index wineventlog (Settings > Indexes > New Index).
Enable receiving on port 9997 (Settings > Forwarding and receiving > Configure receiving).
Step 2: Audit Policy Configuration

Configured advanced audit subcategories on the Windows 11 VM using the Local Security Policy (secpol.msc):

Audit Logon: logon events (Event ID 4624, 4625)
Audit User Account Management: account creation and changes (Event ID 4720)
Audit Security Group Management: group membership changes (Event ID 4732)

System clocks were synchronized to keep log timestamps accurate.

Step 3: Attack Simulation and Reproduction Commands

Simulated adversary techniques mapped to MITRE ATT&CK:

Stage	Technique	Event ID
Brute-force attempt (Credential Access)	T1110 - Brute Force	4625
Successful authentication	T1078 - Valid Accounts	4624
Persistence account created	T1136.001 - Create Account: Local Account	4720
Added to privileged group	T1098.007 - Account Manipulation: Additional Local or Domain Groups	4732

Commands used to create the account and grant administrator rights:

cmd
net user hack_admin P@ssw0rd123! /add
net localgroup administrators hack_admin /add

The password above is for this isolated lab only. Never reuse it.

Step 4: Log Forwarding Configuration

Configured the Universal Forwarder on the Windows 11 endpoint (C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf):

ini
[default]
host = Windows11-Victim-VM

[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
index = wineventlog

[WinEventLog://System]
disabled = 0
index = wineventlog

[WinEventLog://Application]
disabled = 0
index = wineventlog

The forwarder sends data to the SIEM host using outputs.conf (see configs/outputs.conf).

5. Log Analysis, SPL Investigations and Correlation

Field names depend on how Splunk parses the Windows events. The queries below use the default field names observed in this lab.

5.1. Detecting Brute-Force Activity (Event ID 4625)

MITRE ATT&CK: T1110 - Brute Force

spl
index=wineventlog EventCode=4625
| eval Target_User=mvindex(Account_Name, 1)
| stats count by Target_User, Source_Network_Address
| sort - count

Findings: Identified a high number of failed logons against the local administrator account.

Evidence:

4625 brute force

5.2. Investigating Unauthorized User Creation (Event ID 4720)

MITRE ATT&CK: T1136.001 - Create Account: Local Account

spl
index=wineventlog EventCode=4720
| eval Created_By=mvindex(Account_Name, 0), New_Account=mvindex(Account_Name, 1)
| table _time, Computer, New_Account, Created_By

Findings: Identified the exact timestamp, the new account (hack_admin), and the account that created it.

Evidence:

4720 user creation

5.3. Privileged Group Modification (Event ID 4732)

MITRE ATT&CK: T1098.007 - Account Manipulation: Additional Local or Domain Groups

spl
index=wineventlog EventCode=4732
| table _time, Computer, Group_Name, Account_Name

Findings: Confirmed that the new account was added to the local Administrators group.

Evidence:

4732 group modification

5.4. Attack Chain Correlation

This query combines the four event types into one timeline and filters out background logon noise by keeping only interactive, network, and remote interactive logons.

spl
index=wineventlog (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR (EventCode=4624 LogonType IN (2,3,10)))
| eval Attack_Stage=case(
    EventCode=4625, "1. Brute-Force Attempt",
    EventCode=4624, "2. Successful Logon",
    EventCode=4720, "3. Persistence Account Created",
    EventCode=4732, "4. Added to Administrators Group")
| sort _time
| table _time, Computer, Attack_Stage, Account_Name, Source_Network_Address

Events 4720 and 4732 do not include a source IP, so that column is blank for those rows.

6. Mini Incident Report (Lab Simulation)

Summary: A simulated multi-stage attack in which the endpoint saw repeated failed logons (4625), then a successful logon (4624), followed by creation of a local account (4720) and its addition to the Administrators group (4732).

Timeline (from Splunk logs):

Time	Event
2026-11-07 21:14:03	Multiple failed logons against the local admin account (4625)
2026-11-07 21:19:45	Successful logon (4624)
2026-11-07 21:22:10	Local account hack_admin created (4720)
2026-11-07 21:23:55	hack_admin added to Administrators (4732)

Indicators of Compromise (lab):

New local account: hack_admin
Group modified: Administrators

Impact (in a real environment): Persistent administrator-level access and a high risk of further privilege abuse.

Response and Remediation:

Deleted the unauthorized account hack_admin.
Recommended: rotate credentials for affected accounts.
Recommended: enforce an account lockout policy (for example, lock after 5 failed attempts in 10 minutes).
Recommended: regularly review local Administrators membership and alert on Event ID 4732.
7. Detection Engineering: Alert Rule (Proposed)

A scheduled alert to flag repeated failed logons:

Time range: last 10 minutes
Schedule (cron): */10 * * * *
Trigger: number of results > 0
Severity: Medium
spl
index=wineventlog EventCode=4625
| eval Target_User=mvindex(Account_Name, 1)
| stats count by Target_User, Source_Network_Address
| where count >= 5
8. Skills Demonstrated, Lessons Learned and Next Steps

Skills demonstrated: Splunk deployment and index management, Universal Forwarder configuration, Windows Event Log analysis, SPL queries, MITRE ATT&CK mapping, event correlation, incident documentation.

Lessons learned: Correlating events (4625 -> 4624 -> 4720 -> 4732) gave much clearer context than reading each event on its own.
