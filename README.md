SOC Analyst Home Lab: Windows Security Monitoring & Incident Investigation
1. Project Overview

This project demonstrates a foundational Security Operations Center (SOC) workflow. A Windows 11 virtual machine forwards Security Event Logs to Splunk Enterprise, where a simulated multi-stage incident is investigated: failed logons, a successful logon, creation of a local account, and its addition to the local Administrators group.

All activity was performed in an isolated lab for learning purposes.

2. Lab Architecture and Environment
Component	Details
SIEM	Splunk Enterprise (receiving enabled on TCP 9997)
Endpoint	Windows 11 VM in VMware Workstation (Windows hostname SOCLAB, Splunk host label Windows11-Victim-VM)
Agent	Splunk Universal Forwarder
Log source	WinEventLog://Security
Index	wineventlog
Time zone	Eastern Time (UTC-05:00); all times below are VM local time
text
[Windows 11 VM]
     |  Security events: 4625 -> 4624 -> 4720 -> 4732
     v  Splunk Universal Forwarder (TCP 9997)
[Splunk Enterprise - index: wineventlog]
3. Repository Structure
text
SOC-Analyst-HomeLab/
├── README.md
├── configs/
│   └── inputs.conf
└── screenshots/
    ├── 01_audit_policy.png
    ├── 02_inputs_conf.png
    ├── 03_forwarder_running.png
    ├── 04_failed_logons_4625.png
    ├── 05_account_created_4720.png
    ├── 06_group_change_4732.png
    ├── 07_attack_chain.png
    └── 08_time_settings.png
4. Setup
Step 1: Splunk index and receiver
Created the index wineventlog (Settings > Indexes).
Enabled receiving on port 9997 (Settings > Forwarding and receiving).
Step 2: Audit policy

Enabled advanced audit policy categories in the Local Group Policy Editor on the Windows VM:

Logon/Logoff (Event IDs 4624, 4625)
Account Management (Event IDs 4720 and 4732, via User Account Management and Security Group Management)

Audit policy

The VM uses Eastern Time (UTC-05:00) with automatic time sync, so event timestamps are consistent.

Time settings

Step 3: Log forwarding

Configured C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf:

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

inputs.conf

The SplunkForwarder service runs automatically:

Forwarder service

Step 4: Attack simulation

Commands run on the VM:

cmd
net use \\localhost /user:administrator FakePassword123!
net user hack_admin FakePassword123! /add
net localgroup administrators hack_admin /add

FakePassword123! is a throwaway lab password. Never reuse it.

Activity	MITRE ATT&CK	Event ID
Failed logon attempts	T1110 - Brute Force (simulated)	4625
Successful logon	T1078 - Valid Accounts	4624
Local account created	T1136.001 - Create Account: Local Account	4720
Account added to Administrators	T1098.007 - Account Manipulation: Additional Local or Domain Groups	4732
5. Log Analysis and SPL Investigations

In these events, Account_Name holds two values: the first is the account that performed the action (or - / the machine account), and the second is the target account.

5.1. Failed logons (Event ID 4625)
spl
index=wineventlog EventCode=4625
| eval Target_User=mvindex(Account_Name, 1)
| stats count by Target_User, Logon_Type, Source_Network_Address
| sort - count

Findings: 5 failed logons: 1 network logon (Logon_Type 3) against administrator from ::1, and 4 interactive logons (Logon_Type 2) against SOC from 127.0.0.1. The source is loopback because the attack was run locally.

Failed logons

5.2. Local account creation (Event ID 4720)
spl
index=wineventlog EventCode=4720
| eval Created_By=mvindex(Account_Name, 0), New_Account=mvindex(Account_Name, 1)
| table _time, ComputerName, New_Account, Created_By

Findings: hack_admin was created by SOC at 2026-11-08 02:27:24.

Account created

5.3. Local group change (Event ID 4732)
spl
index=wineventlog EventCode IN (4720, 4732)
| table _time, EventCode, ComputerName, Group_Name, Account_Name, Security_ID

Findings: At 2026-11-08 02:34:08, SOC added a member to the Administrators group (group SID S-1-5-32-544). Event 4732 records the member by SID (the member Account_Name shows -). The member SID S-1-5-21-...-1004 matches the SID of the new account hack_admin in event 4720, confirming that hack_admin was added to Administrators.

Group change

5.4. Attack chain correlation

Combines the four event types into one timeline. Only interactive, network and remote interactive logons (Logon_Type 2, 3, 10) are kept, to filter out service and system logons.

spl
index=wineventlog (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR (EventCode=4624 Logon_Type IN (2,3,10)))
| eval Attack_Stage=case(
    EventCode=4625, "1. Failed Logon",
    EventCode=4624, "2. Successful Logon",
    EventCode=4720, "3. Local Account Created",
    EventCode=4732, "4. Added to Local Group")
| sort _time
| table _time, ComputerName, EventCode, Attack_Stage, Account_Name, Group_Name, Logon_Type, Source_Network_Address

Two 4624 events appear at the same timestamp because Windows creates a second, elevated logon session for administrator accounts. 4720 and 4732 have no source address, so that column is blank for those rows.

Attack chain

6. Mini Incident Report (Lab Simulation)

Summary: A simulated sequence in which failed logons were followed by a successful logon, then creation of a local account and its addition to the local Administrators group.

Timeline (from Splunk, VM local time):

Time	Event ID	Description
2026-11-08 02:17:47	4625	Failed network logon for administrator (from ::1)
2026-11-08 02:20:27 - 02:20:34	4625 (x4)	Failed interactive logons for SOC
2026-11-08 02:20:37	4624	Successful interactive logon for SOC
2026-11-08 02:27:24	4720	Local account hack_admin created by SOC
2026-11-08 02:34:08	4732	Member added to Administrators by SOC

Indicators of Compromise (lab):

New local account: hack_admin
Group modified: Administrators

Impact (in a real environment): Persistent administrator-level access and a high risk of further privilege abuse.

Recommended response:

Disable and delete the unauthorized account (net user hack_admin /delete).
Review the membership of the local Administrators group.
Rotate credentials for accounts that saw failed or suspicious logons.
Enforce an account lockout policy (for example, lock after 5 failed attempts in 10 minutes).
7. Detection Engineering: Alert Rule (Proposed)

Scheduled alert for repeated failed logons:

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

Skills demonstrated: Splunk index and receiver setup, Universal Forwarder configuration, Windows audit policy, Windows Event Log analysis, SPL (field extraction with mvindex, stats, eval/case), MITRE ATT&CK mapping, event correlation, incident documentation.

Lessons learned:

Events were only searchable after the index existed and the forwarder was restarted with the correct index setting.
Windows events carry two Account_Name values (actor and target), so reading the right one matters for accurate findings.
Correlating 4625 -> 4624 -> 4720 -> 4732 gave clearer context than reading each event alone.
