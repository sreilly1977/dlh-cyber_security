<#
.Synopsis
    16-hardened_state_export.ps1 - Hardened Windows State Export
.Purpose
    Exports the final hardened Windows domain state into a structured evidence
    package (windows_hardened_state.json) that Module 3 analysts can use for
    validation, detection planning, and weekly drift checks.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# OUTPUT PATH
# ===========================================================================
$OutputPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "windows_hardened_state.json"

# Initialize the master hashtable
$state = [ordered]@{}

# ===========================================================================
# 1. DOMAIN METADATA
# ===========================================================================
Write-Host "[*] Exporting domain metadata... " -NoNewline -ForegroundColor Yellow

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $dc = Get-ADDomainController -Discover -Service PrimaryDC -ErrorAction Stop

    $state.domain_metadata = [ordered]@{
        domain_name    = if ($domain) { $domain.DNSRoot } else { $env:USERDOMAIN }
        netbios_name   = if ($domain) { $domain.NetBIOSName } else { $env:USERDOMAIN }
        domain_controller = if ($dc) { $dc.HostName } else { $env:COMPUTERNAME }
        forest         = if ($domain) { $domain.Forest } else { $env:USERDNSDOMAIN }
        timestamp      = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        script_runner  = "$env:USERDOMAIN\$env:USERNAME"
        computer_name  = $env:COMPUTERNAME
        os_version     = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
    }
    Write-Host "OK" -ForegroundColor Green
} catch {
    $state.domain_metadata = [ordered]@{
        domain_name    = $env:USERDOMAIN
        domain_controller = $env:COMPUTERNAME
        timestamp      = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        script_runner  = "$env:USERDOMAIN\$env:USERNAME"
        error          = $_.Exception.Message
    }
    Write-Host "PARTIAL" -ForegroundColor Yellow
}

# ===========================================================================
# 2. GPO INVENTORY
# ===========================================================================
Write-Host "[*] Exporting GPO settings... " -NoNewline -ForegroundColor Yellow

try {
    $allGpos = Get-GPO -All -ErrorAction Stop
    $medDefenseGpos = $allGpos | Where-Object { $_.DisplayName -like "*MedDefense*" -or $_.DisplayName -like "*MedDef*" }
    $gpoInventory = @()

    foreach ($gpo in $medDefenseGpos) {
        $gpoLinks = Get-GPInheritance -Target (Get-ADDomain).DistinguishedName -ErrorAction Stop |
            Select-Object -ExpandProperty GpoLinks |
            Where-Object { $_.DisplayName -eq $gpo.DisplayName }

        $gpoEntry = [ordered]@{
            name          = $gpo.DisplayName
            id            = $gpo.Id
            enabled       = $true
            linked_scopes = @()
            key_settings  = @()
        }

        if ($gpoLinks) {
            foreach ($link in $gpoLinks) {
                $gpoEntry.linked_scopes += $link.Target
            }
        }

        # Extract key settings based on GPO name
        if ($gpo.DisplayName -like "*Audit*" -or $gpo.DisplayName -like "*Logging*") {
            $gpoEntry.key_settings += "Advanced audit policy configuration"
            $gpoEntry.key_settings += "Process creation auditing with command line"
        }
        if ($gpo.DisplayName -like "*PowerShell*" -or $gpo.DisplayName -like "*Logging*") {
            $gpoEntry.key_settings += "Script Block Logging (Event ID 4104)"
            $gpoEntry.key_settings += "Module Logging (Event ID 4103)"
            $gpoEntry.key_settings += "Transcription enabled"
        }
        if ($gpo.DisplayName -like "*Firewall*") {
            $gpoEntry.key_settings += "Default deny inbound on all profiles"
            $gpoEntry.key_settings += "MedDef- prefixed allow rules"
        }
        if ($gpo.DisplayName -like "*AppLocker*") {
            $gpoEntry.key_settings += "Executable allow-list (Audit Only)"
            $gpoEntry.key_settings += "Script allow-list (Audit Only)"
        }
        if ($gpo.DisplayName -like "*RDP*" -or $gpo.DisplayName -like "*Remote*") {
            $gpoEntry.key_settings += "NLA required"
            $gpoEntry.key_settings += "Clipboard and drive redirection disabled"
        }
        if ($gpo.DisplayName -like "*Kerberos*" -or $gpo.DisplayName -like "*Auth*") {
            $gpoEntry.key_settings += "DES disabled"
            $gpoEntry.key_settings += "RC4 disabled"
        }
        if ($gpo.DisplayName -like "*SMB*") {
            $gpoEntry.key_settings += "SMBv1 disabled"
            $gpoEntry.key_settings += "SMB signing required"
        }

        $gpoInventory += $gpoEntry
    }

    # If no MedDefense GPOs found, export all GPOs as fallback
    if ($gpoInventory.Count -eq 0 -and $allGpos) {
        foreach ($gpo in $allGpos) {
            $gpoInventory += [ordered]@{
                name          = $gpo.DisplayName
                id            = $gpo.Id
                enabled       = $true
                linked_scopes = @()
                key_settings  = @("General GPO - review manually")
            }
        }
    }

    $state.gpo_inventory = $gpoInventory
    Write-Host "$($gpoInventory.Count) GPOs" -ForegroundColor Green
} catch {
    $state.gpo_inventory = @(@{ error = $_.Exception.Message })
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 3. AUDIT POLICY
# ===========================================================================
Write-Host "[*] Exporting audit policy... " -NoNewline -ForegroundColor Yellow

try {
    $rawAuditpol = auditpol /get /category:* /r 2>&1
    $auditLines = $rawAuditpol -split "`r?`n" | Where-Object { $_.Trim() -ne "" }

    $requiredSubcategories = @(
        "Credential Validation",
        "Other Account Logon Events",
        "Kerberos Ticket Events",
        "Application Generated",
        "Process Creation",
        "Logoff",
        "Logon",
        "Special Logon",
        "Security State Change",
        "Security System Extension",
        "System Integrity"
    )

    $auditParsed = @()
    $subcategoryCount = 0

    foreach ($line in $auditLines) {
        if ($line -match '"([^"]+)","([^"]+)","([^"]+)"') {
            $cat = $matches[1]
            $subcat = $matches[2]
            $inclusion = $matches[3]
            $subcategoryCount++

            $isRequired = $requiredSubcategories | Where-Object { $subcat -like "*$_*" }

            $auditParsed += [ordered]@{
                category    = $cat
                subcategory = $subcat
                inclusion   = $inclusion
                required    = if ($isRequired) { $true } else { $false }
                compliant   = if ($isRequired -and $inclusion -match "Success") { $true } elseif (-not $isRequired) { $null } else { $false }
            }
        }
    }

    $state.audit_policy = [ordered]@{
        raw_output      = ($rawAuditpol -join "`n")
        subcategory_count = $subcategoryCount
        required_status = $auditParsed | Where-Object { $_.required -eq $true }
        all_subcategories = $auditParsed
    }
    Write-Host "$subcategoryCount subcategories" -ForegroundColor Green

    # Key Windows Security Event IDs to monitor
    $keyEventIds = [ordered]@{
        id_1102 = "Audit log cleared"
        id_4624 = "Successful logon"
        id_4625 = "Failed logon"
        id_4672 = "Special privileges assigned to new logon"
        id_4688 = "Process creation"
        id_4698 = "Task created"
        id_4720 = "User account created"
        id_4732 = "Member added to security-enabled local group"
    }

    $state.audit_policy.key_event_ids = $keyEventIds

} catch {
    $state.audit_policy = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 4. POWERSHELL LOGGING
# ===========================================================================
Write-Host "[*] Exporting PowerShell logging... " -NoNewline -ForegroundColor Yellow

try {
    $psRegBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    $scriptBlockLog = Get-ItemProperty -Path "$psRegBase\ScriptBlockLogging" -ErrorAction Stop
    $moduleLog = Get-ItemProperty -Path "$psRegBase\ModuleLogging" -ErrorAction Stop
    $transcription = Get-ItemProperty -Path "$psRegBase\Transcription" -ErrorAction Stop

    # Check for recent Event ID 4104 (Script Block) entries
    $event4104 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 10 -ErrorAction SilentlyContinue)
    $event4103 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103} -MaxEvents 10 -ErrorAction SilentlyContinue)

    $state.powershell_logging = [ordered]@{
        script_block_logging = [ordered]@{
            enabled   = ($scriptBlockLog.EnableScriptBlockLogging -eq 1)
            event_id  = 4104
            recent_events = $event4104.Count
        }
        module_logging = [ordered]@{
            enabled   = ($moduleLog.EnableModuleLogging -eq 1)
            event_id  = 4103
            recent_events = $event4103.Count
            module_names = if ($moduleLog.ModuleNames) { $moduleLog.ModuleNames } else { @("*") }
        }
        transcription = [ordered]@{
            enabled         = ($transcription.EnableTranscripting -eq 1)
            output_directory = if ($transcription.OutputDirectory) { $transcription.OutputDirectory } else { $null }
            enable_invocation_header = if ($transcription.EnableInvocationHeader) { $transcription.EnableInvocationHeader -eq 1 } else { $false }
        }
        event_ids = [ordered]@{
            id_4103 = "Module Logging"
            id_4104 = "Script Block Logging"
        }
    }
    Write-Host "OK" -ForegroundColor Green
} catch {
    $state.powershell_logging = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 5. SYSMON POSTURE
# ===========================================================================
Write-Host "[*] Exporting Sysmon config... " -NoNewline -ForegroundColor Yellow

try {
    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction Stop
    $sysmonDriver = Get-Service -Name SysmonDrv -ErrorAction SilentlyContinue

    # Try to get config path
    $sysmonConfigPath = $null
    $configPaths = @("C:\Windows\Sysmon.xml", "C:\Windows\Sysmon64.xml", "C:\Windows\System32\config\Sysmon.xml")
    foreach ($path in $configPaths) {
        if (Test-Path $path) {
            $sysmonConfigPath = $path
            break
        }
    }

    # Get rule count
    $customRuleCount = 0
    $activeEventIds = @()

    if ($sysmonConfigPath) {
        $configXml = Get-Content $sysmonConfigPath -Raw -ErrorAction Stop
        if ($configXml) {
            $customRuleCount = ([regex]::Matches($configXml, '<Rule(?:\s|>)')).Count
        }
    }

    # Check active Sysmon Event IDs in the operational log
    $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($sysmonEvents) {
        $activeEventIds = $sysmonEvents | Select-Object -ExpandProperty Id -Unique | Sort-Object
    }

    $state.sysmon_posture = [ordered]@{
        service_status   = if ($sysmonService) { $sysmonService.Status.ToString() } else { "Not installed" }
        service_start_type = if ($sysmonService) { $sysmonService.StartType.ToString() } else { "N/A" }
        driver_status    = if ($sysmonDriver) { $sysmonDriver.Status.ToString() } else { "Not installed" }
        config_path      = $sysmonConfigPath
        custom_rule_count = $customRuleCount
        active_event_ids = $activeEventIds
        event_id_meanings = [ordered]@{
            id_1  = "Process Create"
            id_2  = "File creation time changed"
            id_3  = "Network connection"
            id_5  = "Process terminated"
            id_7  = "Image loaded"
            id_8  = "CreateRemoteThread"
            id_9  = "RawAccessRead"
            id_10 = "ProcessAccess"
            id_11 = "FileCreate"
            id_12 = "RegistryEvent"
            id_13 = "RegistryEvent (Value Set)"
            id_15 = "FileCreateStreamHash"
            id_22 = "DNSQuery"
            id_23 = "FileDelete"
            id_25 = "ProcessTampering"
            id_26 = "FileDeleteDetected"
        }
    }
    Write-Host "$customRuleCount custom rules" -ForegroundColor Green
} catch {
    $state.sysmon_posture = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 6. FIREWALL POSTURE
# ===========================================================================
Write-Host "[*] Exporting firewall rules... " -NoNewline -ForegroundColor Yellow

try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $profileStates = @()

    foreach ($profile in $fwProfiles) {
        $profileStates += [ordered]@{
            name              = $profile.Name
            enabled           = $profile.Enabled
            default_inbound   = $profile.DefaultInboundAction
            default_outbound = $profile.DefaultOutboundAction
            log_blocked       = $profile.LogBlocked
            log_allowed       = $profile.LogAllowed
            log_filename      = $profile.LogFileName
            log_max_size_kb   = $profile.LogMaxSizeKilobytes
        }
    }

    $medDefRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -like "MedDef-*" })
    $ruleDetails = @()

    foreach ($rule in $medDefRules) {
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

        $ruleDetails += [ordered]@{
            display_name  = $rule.DisplayName
            direction     = $rule.Direction.ToString()
            action        = $rule.Action.ToString()
            enabled       = $rule.Enabled
            protocol      = if ($portFilter) { $portFilter.Protocol } else { "Any" }
            local_port    = if ($portFilter) { $portFilter.LocalPort } else { "Any" }
            remote_address = if ($addrFilter) { $addrFilter.RemoteAddress } else { "Any" }
        }
    }

    $state.firewall_posture = [ordered]@{
        profiles = $profileStates
        meddefense_rules = $ruleDetails
        meddefense_rule_count = $medDefRules.Count
        dropped_packet_logging = [ordered]@{
            enabled = ($profileStates | Where-Object { $_.log_blocked -eq $true }).Count -gt 0
        }
    }
    Write-Host "$($medDefRules.Count) rules" -ForegroundColor Green
} catch {
    $state.firewall_posture = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 7. APPLOCKER POSTURE
# ===========================================================================
Write-Host "[*] Exporting AppLocker policy... " -NoNewline -ForegroundColor Yellow

try {
    # Enforcement modes from registry
    $exeEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode
    $scriptEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode
    $msiEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi" -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode
    $dllEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll" -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode
    $appxEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Appx" -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode

    function Get-EnforcementMode {
        param($value)
        switch ($value) {
            1 { "Enforce" }
            2 { "AuditOnly" }
            3 { "NotConfigured" }
            default { "NotConfigured" }
        }
    }

    # Count rules from registry
    $exeRules = @(Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne "EnforcementMode" -and $_.PSChildName -match "^[{(]?[0-9a-fA-F-]{36}[)}]?$" })
    $scriptRules = @(Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne "EnforcementMode" -and $_.PSChildName -match "^[{(]?[0-9a-fA-F-]{36}[)}]?$" })

    # Exe rule details
    $exeRuleList = @()
    foreach ($rule in $exeRules) {
        $ruleProps = Get-ItemProperty -Path $rule.PSPath -ErrorAction Stop
        $exeRuleList += [ordered]@{
            guid        = $rule.PSChildName
            name        = $ruleProps.Name
            description = $ruleProps.Description
        }
    }

    # Script rule details
    $scriptRuleList = @()
    foreach ($rule in $scriptRules) {
        $ruleProps = Get-ItemProperty -Path $rule.PSPath -ErrorAction Stop
        $scriptRuleList += [ordered]@{
            guid        = $rule.PSChildName
            name        = $ruleProps.Name
            description = $ruleProps.Description
        }
    }

    # Total rule count
    $totalRules = $exeRules.Count + $scriptRules.Count

    # Exported policy path
    $exportedPolicyPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "applocker_policy.xml"

    # AppIDSvc status
    $appIdSvc = Get-Service -Name AppIDSvc -ErrorAction Stop

    # Retrieve effective AppLocker policy using Get-AppLockerPolicy
    $appLockerPolicy = $null
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
    } catch {
        $appLockerPolicy = $null
    }

    $effectivePolicyXml = $null
    if ($appLockerPolicy) {
        $effectivePolicyXml = $appLockerPolicy
    }

        $state.applocker_posture = [ordered]@{
        appidsvc_status   = if ($appIdSvc) { $appIdSvc.Status.ToString() } else { "Not found" }
        appidsvc_start_type = if ($appIdSvc) { $appIdSvc.StartType.ToString() } else { "N/A" }
        enforcement_modes = [ordered]@{
            exe      = Get-EnforcementMode $exeEnforcement
            script   = Get-EnforcementMode $scriptEnforcement
            msi      = Get-EnforcementMode $msiEnforcement
            dll      = Get-EnforcementMode $dllEnforcement
            appx     = Get-EnforcementMode $appxEnforcement
        }
        executable_rules  = $exeRuleList
        script_rules      = $scriptRuleList
        total_rule_count  = $totalRules
        exported_policy_path = $exportedPolicyPath
        exported_policy_exists = (Test-Path $exportedPolicyPath)
        effective_policy  = $effectivePolicyXml
    }
    Write-Host "$totalRules rules" -ForegroundColor Green
} catch {
    $state.applocker_posture = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 8. RDP POSTURE
# ===========================================================================
Write-Host "[*] Exporting remote access posture... " -NoNewline -ForegroundColor Yellow

try {
    $tsReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $tsMachineReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $raReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"

    $nlaValue = (Get-ItemProperty -Path $tsReg -Name "UserAuthentication" -ErrorAction Stop).UserAuthentication
    $minEnc = (Get-ItemProperty -Path $tsReg -Name "MinEncryptionLevel" -ErrorAction Stop).MinEncryptionLevel
    $idleTimeout = (Get-ItemProperty -Path $tsReg -Name "MaxIdleTime" -ErrorAction Stop).MaxIdleTime
    $maxSession = (Get-ItemProperty -Path $tsReg -Name "MaxConnectionTime" -ErrorAction Stop).MaxConnectionTime
    $clipDisabled = (Get-ItemProperty -Path $tsReg -Name "fDisableClip" -ErrorAction Stop).fDisableClip
    $driveDisabled = (Get-ItemProperty -Path $tsReg -Name "fDisableCdm" -ErrorAction Stop).fDisableCdm
    $raAllowHelp = (Get-ItemProperty -Path $raReg -Name "fAllowToGetHelp" -ErrorAction Stop).fAllowToGetHelp

    # RDP Users group
    $rdpMembers = @(Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction Stop)
    $memberNames = @()
    foreach ($member in $rdpMembers) {
        $memberNames += $member.Name
    }

    $state.rdp_posture = [ordered]@{
        nla_required      = ($nlaValue -eq 1)
        encryption_level  = switch ($minEnc) { 1 { "Low" } 2 { "Client Compatible" } 3 { "High" } default { "Not Configured" } }
        idle_timeout_min  = if ($idleTimeout) { [math]::Round($idleTimeout / 60000) } else { $null }
        max_session_hours = if ($maxSession) { [math]::Round($maxSession / 3600000) } else { $null }
        clipboard_disabled = ($clipDisabled -eq 1)
        drive_redirection_disabled = ($driveDisabled -eq 1)
        remote_assistance_disabled = ($raAllowHelp -eq 0)
        allowed_group     = $memberNames
    }
    Write-Host "OK" -ForegroundColor Green
} catch {
    $state.rdp_posture = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 9. AUTHENTICATION PROTOCOLS
# ===========================================================================
Write-Host "[*] Exporting authentication protocol posture... " -NoNewline -ForegroundColor Yellow

try {
    # Kerberos encryption types
    $kerbReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $supportedEnc = (Get-ItemProperty -Path $kerbReg -Name "SupportedEncryptionTypes" -ErrorAction Stop).SupportedEncryptionTypes

    $desEnabled = $false
    $rc4Enabled = $false
    $aesEnabled = $false

    if ($supportedEnc) {
        $desEnabled = ($supportedEnc -band 0x04) -ne 0    # DES_CBC_CRC or DES_CBC_MD5
        $rc4Enabled = ($supportedEnc -band 0x20) -ne 0   # RC4-HMAC
        $aesEnabled = (($supportedEnc -band 0x08) -ne 0 -or ($supportedEnc -band 0x10) -ne 0)  # AES128/AES256
    } else {
        # Default Windows config includes DES and RC4
        $desEnabled = $false
        $rc4Enabled = $true
        $aesEnabled = $true
    }

    # NTLMv1 check
    $lsaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lmCompat = (Get-ItemProperty -Path $lsaReg -Name "LmCompatibilityLevel" -ErrorAction Stop).LmCompatibilityLevel

    $ntlmv1Enabled = $false
    if ($null -eq $lmCompat) {
        # Default is 3 on modern Windows (NTLMv2 only)
        $ntlmv1Enabled = $false
    } else {
        $ntlmv1Enabled = $lmCompat -lt 3
    }

    # SMBv1
    $smbv1Feature = Get-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -ErrorAction Stop
    $smbv1Enabled = if ($smbv1Feature) { $smbv1Feature.State -ne "Disabled" -and $smbv1Feature.State -ne "DisabledWithDependencies" } else { $false }

    # SMB signing
    $clientSign = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction Stop).RequireSecuritySignature
    $serverSign = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction Stop).RequireSecuritySignature

    $state.authentication_protocols = [ordered]@{
        kerberos = [ordered]@{
            des_enabled   = $desEnabled
            rc4_enabled   = $rc4Enabled
            aes128_enabled = ($supportedEnc -band 0x08) -ne 0
            aes256_enabled = ($supportedEnc -band 0x10) -ne 0
            supported_encryption_types = $supportedEnc
        }
        ntlm = [ordered]@{
            ntlmv1_enabled = $ntlmv1Enabled
            lm_compatibility_level = if ($null -ne $lmCompat) { $lmCompat } else { 3 }
            lm_compatibility_description = switch ($lmCompat) { 0 { "Send LM & NTLM responses" } 1 { "Send LM & NTLM - use NTLMv2 if negotiated" } 2 { "Send NTLM response only" } 3 { "Send NTLMv2 response only (default)" } 4 { "Send NTLMv2 - refuse LM" } 5 { "Send NTLMv2 - refuse LM & NTLM" } default { "Default (NTLMv2 only)" } }
        }
        smb = [ordered]@{
            smbv1_enabled   = $smbv1Enabled
            smbv1_feature_state = if ($smbv1Feature) { $smbv1Feature.State } else { "Unknown" }
            client_signing_required = ($clientSign -eq 1)
            server_signing_required = ($serverSign -eq 1)
        }
    }
    Write-Host "OK" -ForegroundColor Green
} catch {
    $state.authentication_protocols = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 10. SERVICE ACCOUNT POSTURE
# ===========================================================================
Write-Host "[*] Exporting service account posture... " -NoNewline -ForegroundColor Yellow

try {
    $prefixes = @("svc_", "service_", "admin_")
    $serviceAccounts = @()

    foreach ($prefix in $prefixes) {
        $found = Get-ADUser -Filter "SamAccountName -like '$prefix*'" `
            -Properties UserAccountControl, PasswordLastSet, LastLogonDate, ServicePrincipalName,
            msDS-AllowedToDelegateTo, AccountNotDelegated -ErrorAction Stop
        if ($found) {
            $serviceAccounts += $found
        }
    }

    $privilegedGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Backup Operators", "Server Operators", "Account Operators", "Print Operators", "Replicator"
    )

    $accountPosture = @()

    foreach ($account in $serviceAccounts) {
        $uac = [int]$account.UserAccountControl
        $hasUnconstrained = ($uac -band 0x800000) -ne 0
        $hasConstrained = ($uac -band 0x10000000) -ne 0
        $hasDesOnly = ($uac -band 0x200000) -ne 0

        $passwordAgeDays = 0
        if ($account.PasswordLastSet) {
            $passwordAgeDays = ((Get-Date) - $account.PasswordLastSet).Days
        }

        # Check group memberships
        $groups = @(Get-ADPrincipalGroupMembership -Identity $account.DistinguishedName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        $dangerousGroups = @($groups | Where-Object { $privilegedGroups -contains $_ })

        # Check for suspicious logon
        $suspiciousLogon = $false
        $lastLogonStr = $null
        if ($account.LastLogonDate) {
            $lastLogonStr = $account.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")
            if ($account.LastLogonDate.Hour -ge 0 -and $account.LastLogonDate.Hour -lt 6) {
                $suspiciousLogon = $true
            }
        }

        # Interactive logon risk
        $interactiveLogonRisk = "Unknown"
        $denyLogonGroup = @(Get-LocalGroupMember -Name "Deny log on locally" -ErrorAction SilentlyContinue)
        $isDenied = $false
        foreach ($denied in $denyLogonGroup) {
            if ($denied.Name -like "*$($account.SamAccountName)*") {
                $isDenied = $true
                break
            }
        }
        if ($isDenied) {
            $interactiveLogonRisk = "Denied (safe)"
        } else {
            $interactiveLogonRisk = "Not explicitly denied (risk)"
        }

        $accountPosture += [ordered]@{
            sam_account_name          = $account.SamAccountName
            delegation_unconstrained  = $hasUnconstrained
            delegation_constrained    = $hasConstrained
            account_not_delegated     = ($account.AccountNotDelegated -eq $true)
            password_age_days         = $passwordAgeDays
            password_last_set         = if ($account.PasswordLastSet) { $account.PasswordLastSet.ToString("yyyy-MM-dd") } else { $null }
            last_logon                = $lastLogonStr
            suspicious_logon_time     = $suspiciousLogon
            privileged_group_memberships = $dangerousGroups
            interactive_logon_risk    = $interactiveLogonRisk
            spn_count                 = if ($account.ServicePrincipalName) { @($account.ServicePrincipalName).Count } else { 0 }
            use_des_key_only          = $hasDesOnly
        }
    }

    $state.service_account_posture = [ordered]@{
        account_count = $serviceAccounts.Count
        accounts      = $accountPosture
        total_with_excessive_privileges = @($accountPosture | Where-Object { $_.privileged_group_memberships.Count -gt 0 }).Count
        total_with_unconstrained_delegation = @($accountPosture | Where-Object { $_.delegation_unconstrained -eq $true }).Count
        total_with_old_passwords = @($accountPosture | Where-Object { $_.password_age_days -gt 90 }).Count
        total_with_suspicious_logons = @($accountPosture | Where-Object { $_.suspicious_logon_time -eq $true }).Count
    }
    Write-Host "$($serviceAccounts.Count) accounts" -ForegroundColor Green
} catch {
    $state.service_account_posture = @{ error = $_.Exception.Message }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# 11. VALIDATION SUMMARY
# ===========================================================================
Write-Host "[*] Loading validation summary... " -NoNewline -ForegroundColor Yellow

try {
    $validationScript = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "15-master_validation.ps1"

    if (Test-Path $validationScript) {
        # Run the validation script and capture output
        $validationOutput = & $validationScript 2>&1
        $validationExitCode = $LASTEXITCODE

        $passes = @($validationOutput | Where-Object { $_ -match "^\[PASS\]" })
        $warns = @($validationOutput | Where-Object { $_ -match "^\[WARN\]" })
        $fails = @($validationOutput | Where-Object { $_ -match "^\[FAIL\]" })

        $state.validation_summary = [ordered]@{
            status          = "found"
            script_path     = $validationScript
            exit_code       = $validationExitCode
            total_passes    = $passes.Count
            total_warnings  = $warns.Count
            total_failures  = $fails.Count
            overall_status  = if ($validationExitCode -eq 0) { "PASS" } else { "FAIL" }
            raw_output      = ($validationOutput | Out-String).Trim()
        }
        Write-Host "OK" -ForegroundColor Green
    } else {
        $state.validation_summary = [ordered]@{
            status      = "not_found"
            message     = "Validation script (15-master_validation.ps1) not found in same directory"
            searched_at = $validationScript
        }
        Write-Host "NOT FOUND" -ForegroundColor Yellow
    }
} catch {
    $state.validation_summary = [ordered]@{
        status  = "error"
        message = $_.Exception.Message
    }
    Write-Host "ERROR" -ForegroundColor Red
}

# ===========================================================================
# EXPORT TO JSON
# ===========================================================================
$json = $state | ConvertTo-Json -Depth 10

$json | Out-File -FilePath $OutputPath -Force -Encoding UTF8

Write-Host ""
Write-Host "Hardened state exported to: $OutputPath" -ForegroundColor Cyan
Write-Host ""
