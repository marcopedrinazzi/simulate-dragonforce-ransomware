# Simulate DragonForce Ransomware with Atomic RedTeam
This is a simple but effective intelligence led simulation of the DragonForce Ransomware TTPs (Tactics, Techniques, and Procedures) with [AtomicRedTeam](https://atomicredteam.io/). This work is based on the blog post of GROUP-IB available [here](https://www.group-ib.com/blog/dragonforce-ransomware/). First of all, I wanna thank [@skandler](https://github.com/skandler), I read his great blog post about [Simulating an Akira Ransomware Attack with Atomic Red Team](https://detect.fyi/simulating-a-akira-ransomware-attack-with-atomic-red-team-9e9d66e7bf60) and I was inspired to create something similar. I followed the same approach that he used and took the core structure of the powershell script that he created and applied it in the scenario of this simulation.

The goal of this project is to simulate the DrafonForce Ransomware TTPs and test the detection capabilities deployed in an environment against well-known adversarial TTPs. 

Any kind of criticism and feedback is very welcomed and appreciated as this was my first time doing an intelligence led simulation :)

## How can I use it?
Run the PowerShell script `simulate_dragonforce.ps1` which is a collection of `Invoke-AtomicTest` commands and some custom tests. You can learn more about Invoke-AtomicRedTeam [here](https://github.com/redcanaryco/invoke-atomicredteam). The script requires administrative privileges.

Before executing the script remember:
- set the parameters for the Atomic Tests, I decided to publish a general version on GitHub in order to leave the customization open to the users.
- you're simulating the behavior a ransomware, execute it in a lab, take a snapshot of your VMs tha you can revert to :) otherwise Invoke-AtomicRedTeam has a nice feature of doing a cleanup after executing the Atomic Tests ([ref](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Cleanup-After-Executing-Atomic-Tests)), so you can customize the script and do that.

##  What is DragonForce?
> DragonForce operates a Ransomware-as-a-Service (RaaS) affiliate program utilizing a variant of LockBit3.0, and the other, though initially claimed as original, is based on ContiV3. The group employs double extortion tactics, encrypting data, and threatening leaks unless a ransom is paid.

Below the TTPs, I added some TTPs which I felt were missing from the table published by GROUP-IB in its blog post but were described in the blog post's sections.

| Tactic            | Technique with ID                                     | Description                                                                 | Notes |
|-------------------|------------------------------------------------------|-----------------------------------------------------------------------------|-------|
| Initial Access     | Valid Accounts (T1078)                               | DragonForce affiliates gain access using compromised valid domain accounts. |   Not implemented. See below (1)    |
| Execution          | Command and Scripting Interpreter: PowerShell (T1059.001) | PowerShell is used to download and execute malicious payloads like Cobalt Strike. |   Developed  a custom test  |
| Execution          | Inter-Process Communication (T1559) | I added this technique to simulate the usage of Cobalt Strike mentioned in the blog post GROUP-IB|   [Atomic Test Reference #1](https://atomicredteam.io/execution/T1559/#atomic-test-1---cobalt-strike-artifact-kit-pipe) [Atomic Test Reference #2](https://atomicredteam.io/execution/T1559/#atomic-test-2---cobalt-strike-lateral-movement-psexec_psh-pipe) [Atomic Test Reference #3](https://atomicredteam.io/execution/T1559/#atomic-test-3---cobalt-strike-ssh-postex_ssh-pipe) [Atomic Test Reference #4](https://atomicredteam.io/execution/T1559/#atomic-test-4---cobalt-strike-post-exploitation-pipe-42-and-later) |
| Persistence        | Valid Accounts: Domain Accounts (T1078.002)          | Maintaining access by using compromised domain accounts.                    |   Not implemented. See below (2)    |
| Persistence        | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) | Registry keys are created to ensure malware execution at startup.          |    [Atomic Test Reference](https://atomicredteam.io/privilege-escalation/T1547.001/#atomic-test-1---reg-key-run) |
| Persistence        | Create or Modify System Process: Windows Service (T1543.003) | SystemBC creates services for persistence.                                  |   [Atomic Test Reference](https://atomicredteam.io/privilege-escalation/T1543.003/#atomic-test-2---service-installation-cmd)   |
| Defense Evasion    | Impair Defenses: Disable or Modify Tools (T1562.001) | I added this technique by reading the GROUP-IB blogpost, the reference is "Antivirus features were disabled"   |    [Atomic Test Reference](https://atomicredteam.io/defense-evasion/T1562.001/#atomic-test-16---tamper-with-windows-defender-atp-powershell)   |
| Credential Access  | OS Credential Dumping: LSASS Memory (T1003.001)      | Mimikatz is used to dump credentials from LSASS memory.                     |   [Atomic Test Reference](https://atomicredteam.io/credential-access/T1003.001/#atomic-test-6---offline-credential-theft-with-mimikatz)    |
| Discovery          | System Network Configuration Discovery (T1016)       | Network configuration details are collected by the attackers.               |   [Atomic Test Reference](https://atomicredteam.io/discovery/T1016/#atomic-test-6---adfind---enumerate-active-directory-subnet-objects)    |
| Discovery          | Domain Trust Discovery (T1482)                       | ADFind tool is used to gather information on the Active Directory.          |   [Atomic Test Reference](https://atomicredteam.io/discovery/T1482/#atomic-test-5---adfind---enumerate-active-directory-trusts)    |
| Discovery          | Remote System Discovery (T1018)                      | Network scanner tools are used to discover remote systems.                  |    [Atomic Test Reference](https://atomicredteam.io/discovery/T1018/#atomic-test-22---enumerate-remote-hosts-with-netscan)   |
| Discovery          | System Information Discovery (T1082)                 | System-specific information is gathered for targeted attacks.               |   [Atomic Test Reference](https://atomicredteam.io/discovery/T1082/#atomic-test-1---system-information-discovery)    |
| Discovery          | File and Directory Discovery (T1083)                 | Attackers explore directories and files for valuable data.                  |   [Atomic Test Reference](https://atomicredteam.io/discovery/T1083/#atomic-test-2---file-and-directory-discovery-powershell)    |
| Lateral Movement   | Remote Services: Remote Desktop Protocol (T1021.001) | RDP is used for lateral movement within the network.                        |    [Atomic Test Reference](https://atomicredteam.io/lateral-movement/T1021.001/#atomic-test-1---rdp-to-domaincontroller)   |
| Command and Control | Application Layer Protocol: Web Protocols (T1071.001) | C2 communication is established using HTTP.                                |    [Atomic Test Reference](https://atomicredteam.io/command-and-control/T1071.001/#atomic-test-1---malicious-user-agents---powershell)   |
| Command and Control |  Exfiltration Over C2 Channel (T1041) | I added this technique since the blog post by GROUP-IB was talking about data being exiltrated (so I assumed an exiltration through the C2 channel)    |    [Atomic Test Reference](https://atomicredteam.io/exfiltration/T1041/#atomic-test-1---c2-data-exfiltration)   |
| Defense Evasion    | Indicator Removal: Clear Windows Event Logs (T1070.001) | Windows Event Logs are cleared to hinder forensic investigation.            |    [Atomic Test Reference](https://atomicredteam.io/defense-evasion/T1070.001/#atomic-test-1---clear-logs)   |
| Impact             | Defacement: Internal Defacement (T1491.001)         | I added this technique since I saw on the blog post by GROUP-IB the change of the wallpaper by the DrangonForce ransomware            |   [Atomic Test Reference](https://atomicredteam.io/impact/T1491.001/#atomic-test-1---replace-desktop-wallpaper)    |
| Impact             | Data Encrypted for Impact (T1486)                    | Ransomware is deployed to encrypt files across multiple systems.            |   Developed  a custom test, adapted from  https://github.com/skandler/simulate-akira   |

(1) (2) Out of the scope of the simulation. It's possible to assume that account X and/or Y are compromised and use them but I decided to omit this technique and focus on more meaningful techniques, I think this technique would suit better in a detailed and more comprehensive *emulation*


# References
- https://www.group-ib.com/blog/dragonforce-ransomware/
- https://detect.fyi/simulating-a-akira-ransomware-attack-with-atomic-red-team-9e9d66e7bf60
- https://github.com/skandler/simulate-akira