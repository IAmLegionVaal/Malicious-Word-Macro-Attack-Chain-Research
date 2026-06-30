#requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows controls relevant to malicious Office macro attack chains.

.DESCRIPTION
    Read-only assessment of:
      - Microsoft Defender Antivirus health
      - Selected Attack Surface Reduction rule states
      - PowerShell logging policy
      - Sysmon service presence
      - Office 16.0 policy-key visibility

    The script does not change endpoint configuration.

.PARAMETER OutputDirectory
    Directory used for JSON and CSV reports.

.PARAMETER PassThru
    Returns findings to the pipeline.

.EXAMPLE
    .\Test-OfficeMacroAttackSurface.ps1 -PassThru

.EXAMPLE
    .\Test-OfficeMacroAttackSurface.ps1 -OutputDirectory C:\Temp\OfficeMacroAudit
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'audit-output'),

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Control,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warning', 'Fail', 'Info', 'Unknown')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Observed,

        [Parameter(Mandatory)]
        [string]$Recommendation
    )

    $findings.Add([pscustomobject]@{
        Timestamp      = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName   = $env:COMPUTERNAME
        Category       = $Category
        Control        = $Control
        Status         = $Status
        Observed       = $Observed
        Recommendation = $Recommendation
    })
}

function Convert-AsrAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Action
    )

    switch ($Action) {
        0 { 'Disabled' }
        1 { 'Block' }
        2 { 'Audit' }
        6 { 'Warn' }
        default { "Unknown($Action)" }
    }
}

function Get-RegistrySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        return $item.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } |
            ForEach-Object {
                [pscustomobject]@{
                    Name  = $_.Name
                    Value = [string]$_.Value
                }
            }
    }
    catch {
        Add-Finding -Category 'Registry' -Control $Path -Status 'Unknown' `
            -Observed $_.Exception.Message `
            -Recommendation 'Review registry permissions and collect the policy through an approved management channel.'
        return $null
    }
}

try {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force

    if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $status = Get-MpComputerStatus

            Add-Finding -Category 'Microsoft Defender Antivirus' `
                -Control 'Real-time protection' `
                -Status $(if ($status.RealTimeProtectionEnabled) { 'Pass' } else { 'Fail' }) `
                -Observed "RealTimeProtectionEnabled=$($status.RealTimeProtectionEnabled)" `
                -Recommendation 'Keep Microsoft Defender Antivirus real-time protection enabled.'

            Add-Finding -Category 'Microsoft Defender Antivirus' `
                -Control 'Behaviour monitoring' `
                -Status $(if ($status.BehaviorMonitorEnabled) { 'Pass' } else { 'Warning' }) `
                -Observed "BehaviorMonitorEnabled=$($status.BehaviorMonitorEnabled)" `
                -Recommendation 'Enable behaviour monitoring unless an approved security architecture provides equivalent coverage.'

            Add-Finding -Category 'Microsoft Defender Antivirus' `
                -Control 'IOAV protection' `
                -Status $(if ($status.IoavProtectionEnabled) { 'Pass' } else { 'Warning' }) `
                -Observed "IoavProtectionEnabled=$($status.IoavProtectionEnabled)" `
                -Recommendation 'Enable scanning of downloaded files and attachments.'
        }
        catch {
            Add-Finding -Category 'Microsoft Defender Antivirus' -Control 'Health query' -Status 'Unknown' `
                -Observed $_.Exception.Message `
                -Recommendation 'Verify Defender health through Microsoft Defender for Endpoint or the endpoint security platform.'
        }
    }
    else {
        Add-Finding -Category 'Microsoft Defender Antivirus' -Control 'Health query' -Status 'Unknown' `
            -Observed 'Get-MpComputerStatus is unavailable.' `
            -Recommendation 'Verify whether Defender Antivirus is installed, disabled, or replaced by another managed antimalware product.'
    }

    $targetRules = [ordered]@{
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    }

    if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $preference = Get-MpPreference
            $configured = @{}
            $ids = @($preference.AttackSurfaceReductionRules_Ids)
            $actions = @($preference.AttackSurfaceReductionRules_Actions)

            for ($index = 0; $index -lt $ids.Count; $index++) {
                $configured[[string]$ids[$index].ToLowerInvariant()] = [int]$actions[$index]
            }

            foreach ($rule in $targetRules.GetEnumerator()) {
                $guid = $rule.Key.ToLowerInvariant()

                if ($configured.ContainsKey($guid)) {
                    $actionName = Convert-AsrAction -Action $configured[$guid]
                    $statusName = switch ($actionName) {
                        'Block' { 'Pass' }
                        'Warn' { 'Warning' }
                        'Audit' { 'Warning' }
                        'Disabled' { 'Fail' }
                        default { 'Unknown' }
                    }

                    Add-Finding -Category 'Attack Surface Reduction' -Control $rule.Value `
                        -Status $statusName `
                        -Observed "$guid=$actionName" `
                        -Recommendation 'Pilot in Audit mode, tune narrow exceptions, then move high-value Office protections to Block.'
                }
                else {
                    Add-Finding -Category 'Attack Surface Reduction' -Control $rule.Value `
                        -Status 'Warning' `
                        -Observed 'Rule is not explicitly configured in local Defender preference output.' `
                        -Recommendation 'Verify the effective Intune, Configuration Manager, Group Policy, or MDM policy.'
                }
            }
        }
        catch {
            Add-Finding -Category 'Attack Surface Reduction' -Control 'ASR query' -Status 'Unknown' `
                -Observed $_.Exception.Message `
                -Recommendation 'Verify effective ASR configuration through the central management plane.'
        }
    }
    else {
        Add-Finding -Category 'Attack Surface Reduction' -Control 'ASR query' -Status 'Unknown' `
            -Observed 'Get-MpPreference is unavailable.' `
            -Recommendation 'Verify effective ASR configuration through the endpoint security platform.'
    }

    $loggingPolicies = @(
        @{
            Name = 'Script Block Logging'
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Value = 'EnableScriptBlockLogging'
        },
        @{
            Name = 'Module Logging'
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            Value = 'EnableModuleLogging'
        },
        @{
            Name = 'PowerShell Transcription'
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            Value = 'EnableTranscripting'
        }
    )

    foreach ($policy in $loggingPolicies) {
        if (Test-Path -LiteralPath $policy.Path) {
            try {
                $value = (Get-ItemProperty -LiteralPath $policy.Path -Name $policy.Value -ErrorAction Stop).$($policy.Value)

                Add-Finding -Category 'PowerShell Logging' -Control $policy.Name `
                    -Status $(if ([int]$value -eq 1) { 'Pass' } else { 'Warning' }) `
                    -Observed "$($policy.Value)=$value" `
                    -Recommendation 'Enable and centralise PowerShell logging according to data-protection and operational requirements.'
            }
            catch {
                Add-Finding -Category 'PowerShell Logging' -Control $policy.Name -Status 'Warning' `
                    -Observed 'Policy key exists but the expected enable value is absent or unreadable.' `
                    -Recommendation 'Review the effective PowerShell logging policy.'
            }
        }
        else {
            Add-Finding -Category 'PowerShell Logging' -Control $policy.Name -Status 'Warning' `
                -Observed 'Policy registry path not found.' `
                -Recommendation 'Enable and centralise PowerShell logging through Group Policy or MDM.'
        }
    }

    $sysmonService = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($null -ne $sysmonService) {
        Add-Finding -Category 'Endpoint Telemetry' -Control 'Sysmon service' `
            -Status $(if ($sysmonService.Status -eq 'Running') { 'Pass' } else { 'Warning' }) `
            -Observed "Name=$($sysmonService.Name); Status=$($sysmonService.Status)" `
            -Recommendation 'Keep Sysmon running with a centrally managed, tested configuration and enable relevant process and network events.'
    }
    else {
        Add-Finding -Category 'Endpoint Telemetry' -Control 'Sysmon service' -Status 'Info' `
            -Observed 'Sysmon service not detected.' `
            -Recommendation 'Use Sysmon or equivalent EDR telemetry for process, file, DNS, and network correlation.'
    }

    $officePolicyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security',
        'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
    )

    foreach ($path in $officePolicyPaths) {
        $snapshot = Get-RegistrySnapshot -Path $path

        if ($null -eq $snapshot) {
            Add-Finding -Category 'Microsoft Word Policy' -Control $path -Status 'Info' `
                -Observed 'Policy key not present or not readable.' `
                -Recommendation 'Verify effective macro policy through Intune, Group Policy, or the Microsoft 365 Apps management plane.'
        }
        else {
            $serialized = ($snapshot | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '

            Add-Finding -Category 'Microsoft Word Policy' -Control $path -Status 'Info' `
                -Observed $serialized `
                -Recommendation 'Confirm that internet macros are blocked and only approved signed macros or controlled locations are trusted.'
        }
    }

    $jsonPath = Join-Path -Path $OutputDirectory -ChildPath 'OfficeMacroAttackSurface.json'
    $csvPath = Join-Path -Path $OutputDirectory -ChildPath 'OfficeMacroAttackSurface.csv'

    $findings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $findings | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host 'Audit completed.'
    Write-Host "JSON: $jsonPath"
    Write-Host "CSV : $csvPath"

    if ($PassThru) {
        $findings
    }
}
catch {
    Write-Error -Message ("Office macro attack-surface audit failed: {0}" -f $_.Exception.Message)
    exit 1
}
