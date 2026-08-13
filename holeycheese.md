# Write-Up: Windows Persistence Techniques — TryHackMe

**Room:** Windows Persistence Techniques  
**Difficulty:** Medium  

---

## Task 1 — Introduction: What Is Persistence?

Theoretical task — no hands-on work. Persistence is MITRE ATT&CK Tactic TA0003. It covers any mechanism that lets an attacker regain access after a reboot, password change, or network disruption. User-level techniques don't require admin privileges — they survive logon-triggered. System-level ones require admin and survive boot-triggered.

---

## Task 2 — Baseline the Host

Before investigating, establish what the clean system looks like.

1. Right-click `Autoruns64.exe` → **Run as administrator**.
2. Go to **Options → Scan Options**:
   - Uncheck *Hide Microsoft entries*
   - Check *Verify code signatures*
   - Optionally check *Check VirusTotal.com*
3. Wait for the scan to finish (watch the status bar at the bottom).
4. **File → Save** → save as `baseline-clean.arn`.

The saved file has the `.arn` extension — this is a binary snapshot. Explore each tab:

- **Services** tab — shows all Windows services
- **Logon** tab — startup folders and Run keys
- **Image Hijacks** — IFEO entries
- **LSA Providers** — authentication and notification packages

Unsigned binaries are highlighted in **pink** — investigate these immediately.

---

## Task 3 — Startup Folder Persistence

**MITRE:** T1547.001

List the per-user Startup folder:

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

Also check the all-users Startup folder:

```powershell
Get-ChildItem "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
```

The per-user folder contains `update-cache.txt`. This file executes at every logon because `explorer.exe` launches everything in these folders.

In Autoruns, switch to the **Logon** tab to see the entry.

**Removal:**

```powershell
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update-cache.txt" -Force
```

---

## Task 4 — Registry Run and RunOnce Keys

**MITRE:** T1547.001

Enumerate all four Run/RunOnce locations:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
```

Or via cmd:

```cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

You will find a value named `sync-agent` under the HKCU Run key. RunOnce values are automatically deleted after execution. Sysmon Event ID 13 (RegistryValueSet) detects these modifications.

**Removal:**

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'sync-agent'
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'sync-agent-once'
```

---

## Task 5 — Scheduled Tasks and PowerShell Profile

**MITRE:** T1053.005 / T1059.001

### Scheduled Task

Find the planted task:

```powershell
Get-ScheduledTask -TaskName 'THM-Persistence-Maintenance'
```

Inspect the trigger type:

```powershell
(Get-ScheduledTask -TaskName 'THM-Persistence-Maintenance').Triggers
```

Output shows the trigger type is `AtLogOn`. Inspect the action (what it runs):

```powershell
(Get-ScheduledTask -TaskName 'THM-Persistence-Maintenance').Actions
```

Export the full XML for detailed analysis:

```powershell
Export-ScheduledTask -TaskName 'THM-Persistence-Maintenance'
```

You can also browse task XML files directly:

```powershell
Get-ChildItem C:\Windows\System32\Tasks\ | Where-Object { $_.Name -like '*THM*' }
Get-Content "C:\Windows\System32\Tasks\THM-Persistence-Maintenance"
```

### PowerShell Profile

Check if a profile exists and read its contents:

```powershell
Test-Path $PROFILE.CurrentUserAllHosts
Get-Content $PROFILE.CurrentUserAllHosts
```

The profile path is typically `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1` (PS 5.1) or `%USERPROFILE%\Documents\PowerShell\profile.ps1` (PS 7+). Inside the file, look for a variable assignment containing `THM{ps_profile_persistence}` — this is the hidden flag. PowerShell profiles do **not** appear in Autoruns, making them a blind spot.

**Removal:**

```powershell
Unregister-ScheduledTask -TaskName 'THM-Persistence-Maintenance' -Confirm:$false

# Remove malicious line from PS profile
$lines = Get-Content $PROFILE.CurrentUserAllHosts
$clean = $lines | Where-Object { $_ -notmatch 'THM' }
Set-Content $PROFILE.CurrentUserAllHosts -Value $clean
```

---

## Task 6 — COM Object Hijacking

**MITRE:** T1546.015

Search the current user's CLSID registry entries:

```powershell
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -Recurse
```

To see just the suspicious entry and its DLL path:

```powershell
Get-ItemProperty 'HKCU:\Software\Classes\CLSID\{THM-PERSISTENCE-COM}\InprocServer32'
```

The CLSID `{THM-PERSISTENCE-COM}` is registered under HKCU. Windows checks HKCU before HKLM when resolving COM CLSIDs, so the attacker's entry shadows any legitimate system-wide one. When any application calls `CoCreateInstance()` for this CLSID, the attacker's DLL loads instead.

**Removal:**

```powershell
Remove-Item 'HKCU:\Software\Classes\CLSID\{THM-PERSISTENCE-COM}' -Recurse -Force
```

---

## Task 7 — File Association Hijacking

**MITRE:** T1546.001

Check for the custom file association:

```powershell
Get-ItemProperty 'HKCU:\Software\Classes\.thmfile'
```

From cmd, you can also use:

```cmd
assoc .thmfile
ftype thmfile.handler
```

Inspect the handler command:

```powershell
Get-ItemProperty 'HKCU:\Software\Classes\thmfile.handler\shell\open\command'
```

The `.thmfile` extension points to ProgID `thmfile.handler`. When any `.thmfile` is double-clicked, the custom command in `shell\open\command` executes.

**Removal:**

```powershell
Remove-Item 'HKCU:\Software\Classes\.thmfile' -Recurse -Force
Remove-Item 'HKCU:\Software\Classes\thmfile.handler' -Recurse -Force
```

---

## Task 8 — Windows Service Persistence

**MITRE:** T1543.003

Query the planted service:

```powershell
Get-Service 'THM-SyncHelper'
```

Get full configuration (binary path, start type, account):

```cmd
sc.exe qc THM-SyncHelper
```

Or in PowerShell:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\THM-SyncHelper'
```

The service has start type `AUTO_START` (value 2), meaning it launches at every boot before any user logs in. All Windows services are defined under `HKLM\SYSTEM\CurrentControlSet\Services`.

**Removal:**

```powershell
sc.exe stop 'THM-SyncHelper'
sc.exe delete 'THM-SyncHelper'
```

---

## Task 9 — Winlogon Persistence

**MITRE:** T1547.004

Examine the Winlogon registry key:

```powershell
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Userinit, Shell
```

Or via cmd:

```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
```

The default `Userinit` value is `C:\Windows\system32\userinit.exe,` — anything appended after the trailing comma is the attacker's persistence implant. `Userinit` executes **before** `explorer.exe`, making it very early in the logon chain.

In Autoruns, check the **Winlogon** tab.

**Removal:**

```powershell
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value 'C:\Windows\system32\userinit.exe,'
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell' -Value 'explorer.exe'
```

---

## Task 10 — Trigger-Based Persistence: Session Lock and Silent Process Exit

**MITRE:** T1053.005 / T1546.012

### Session-Lock Scheduled Task

```powershell
Get-ScheduledTask -TaskName 'THM-Persistence-LockWatcher'
```

Inspect the trigger details:

```powershell
$task = Get-ScheduledTask -TaskName 'THM-Persistence-LockWatcher'
$task.Triggers | Format-List *
```

The trigger is a `SessionStateChangeTrigger` with `StateChange = 7`, which corresponds to the session lock event (Win+L). This task fires every time the user locks their workstation — not at logon, not on a timer — making it invisible to boot-time scans.

### Silent Process Exit

Check IFEO and SilentProcessExit keys for `charmap.exe`:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe'
```

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\charmap.exe"
```

The `GlobalFlag` value is set to `0x200` (FLG_MONITOR_SILENT_PROCESS_EXIT). The `MonitorProcess` value under the SilentProcessExit key specifies the command that runs when `charmap.exe` exits.

**Removal:**

```powershell
Unregister-ScheduledTask -TaskName 'THM-Persistence-LockWatcher' -Confirm:$false
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\charmap.exe' -Recurse -Force
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe' -Name 'GlobalFlag'
```

---

## Task 11 — WMI Event Subscriptions

**MITRE:** T1546.003

Enumerate all three WMI subscription components in the `root\subscription` namespace:

```powershell
# Event Filter — defines the trigger condition (WQL query)
Get-WmiObject -Namespace root\subscription -Class __EventFilter

# Event Consumer — defines the action (command to run)
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer

# Binding — links filter to consumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

The filter is named `WmiSync`, the consumer is `WmiSyncConsumer`. WMI subscriptions are stored in the WMI repository (`C:\Windows\System32\wbem\Repository\`), not the registry — registry-only scanners won't find them. Sysmon Event IDs 19/20/21 detect WMI subscription creation.

**Removal:**

```powershell
$ns = 'root\subscription'
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object {
    $_.Filter -like '*WmiSync*'
} | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='WmiSyncConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='WmiSync'" | Remove-WmiObject
```

---

## Task 12 — IFEO Debugger Hijack

**MITRE:** T1546.012

Check the IFEO key for `calc.exe`:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe'
```

Or:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe"
```

The `Debugger` value is set to `cmd.exe`. When you try to launch Calculator, Windows launches the debugger instead — `cmd.exe` starts, Calculator never does. In Autoruns, this appears under the **Image Hijacks** tab.

A devastating real-world variant targets pre-authentication accessibility tools like `utilman.exe` (Win+U on the lock screen), `sethc.exe` (Sticky Keys), or `osk.exe` (On-Screen Keyboard). Hijacking these gives a SYSTEM shell on the lock screen without any credentials.

**Removal:**

```powershell
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe' -Recurse -Force
```

---

## Task 13 — Active Setup

**MITRE:** T1547.014

Enumerate Active Setup components and filter for suspicious entries:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Select-Object PSChildName, StubPath, Version, IsInstalled
```

To find the specific planted entry:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{THM-ACTIVE-SETUP}'
```

The GUID `{THM-ACTIVE-SETUP}` has a `StubPath` value pointing to the payload. Active Setup runs the StubPath once per user at first logon. Incrementing the `Version` value forces re-execution for all users.

**Removal:**

```powershell
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{THM-ACTIVE-SETUP}' -Recurse -Force
```

---

## Task 14 — LSA Security Packages: Enumeration and Theory

**MITRE:** T1547.005 / T1547.002

Enumerate all three types of LSA packages from the registry:

```powershell
# Notification Packages (Password Filters)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Notification Packages').'Notification Packages'

# Authentication Packages
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Authentication Packages').'Authentication Packages'

# Security Packages (SSPs)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Security Packages').'Security Packages'
```

On a clean Windows 10, the only Notification Packages are `rassfm` (Remote Access Service) and `scecli` (password complexity enforcer). All three values live under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

Compare with the pre-injection baseline:

```powershell
Get-Content "C:\THM-Persistence-Lab\lsa\baseline-before.txt"
```

Check whether LSA Protection is enabled:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
```

If `RunAsPPL = 1`, LSASS runs as a Protected Process Light — only signed DLLs can be loaded.

In Autoruns, check the **LSA Providers** tab — non-Microsoft entries are highlighted in pink.

---

## Task 15 — LSA Persistence: Injection and Detection

**MITRE:** T1547.005 / T1547.002

Compare current Notification Packages against the known-good baseline:

```powershell
$knownGood = @('rassfm', 'scecli')
$packages = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Notification Packages').'Notification Packages'
foreach ($pkg in ($packages | Where-Object { $_ -ne '' })) {
    if ($pkg -in $knownGood) {
        Write-Host "[OK] $pkg" -ForegroundColor Green
    } else {
        Write-Host "[!!] $pkg — SUSPICIOUS" -ForegroundColor Red
    }
}
```

The output reveals `THMNotificationPackage` as a non-default entry. Verify the DLL on disk:

```powershell
Test-Path "C:\Windows\System32\THMNotificationPackage.dll"
Get-Item "C:\Windows\System32\THMNotificationPackage.dll" | Select-Object Name, Length, LastWriteTime
Get-AuthenticodeSignature "C:\Windows\System32\THMNotificationPackage.dll"
```

The DLL must be placed in `C:\Windows\System32` for LSASS to load it. Sysmon Event ID 7 (ImageLoaded) detects modules being loaded into processes.

Check whether LSASS has any outbound network connections (it never should):

```powershell
Get-NetTCPConnection -OwningProcess (Get-Process lsass).Id -ErrorAction SilentlyContinue
```

List all modules currently loaded in LSASS:

```powershell
Get-Process lsass | Select-Object -ExpandProperty Modules | Select-Object FileName
```

**Removal:**

```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = (Get-ItemProperty $lsaPath -Name 'Notification Packages').'Notification Packages'
$cleaned = @($current | Where-Object { $_ -ne 'THMNotificationPackage' -and $_ -ne '' })
Set-ItemProperty $lsaPath -Name 'Notification Packages' -Value $cleaned -Type MultiString
Remove-Item 'C:\Windows\System32\THMNotificationPackage.dll' -Force -ErrorAction SilentlyContinue
# Reboot required to fully unload from LSASS
```

---

## Task 16 — LSA Advanced: Credential Interception and Password Bypass

**MITRE:** T1556.002

Examine the simulated credential capture log:

```powershell
Get-Content "C:\THM-Persistence-Lab\lsa\captured-credentials.log"
```

Count the captured entries:

```powershell
(Get-Content "C:\THM-Persistence-Lab\lsa\captured-credentials.log" | Where-Object { $_ -match 'PasswordChange' }).Count
```

The log contains 3 captured credential entries. The Password Filter API function `PasswordFilter()` receives the plaintext new password before a change is applied. If it returns `TRUE`, the password is accepted regardless of policy.

Check whether WDigest plaintext credential caching is enabled:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
```

If `UseLogonCredential = 1`, LSASS caches plaintext passwords in memory — extractable with Mimikatz `sekurlsa::wdigest`. The Mimikatz "Skeleton Key" attack injects a master password that works on every account alongside the real password.

---
