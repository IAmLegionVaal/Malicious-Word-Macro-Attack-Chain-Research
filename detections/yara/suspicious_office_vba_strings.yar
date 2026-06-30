rule Suspicious_Office_VBA_AutoRun_And_Staging_Strings
{
    meta:
        author = "Dewald Pretorius"
        description = "Triage rule for Office VBA containing auto-run plus multiple process/network staging indicators"
        date = "2026-06-30"
        scope = "Defensive triage only"
        mitre = "T1059.005, T1059.001, T1105, T1564.003"

    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Document_Open" ascii wide nocase
        $exec1 = "powershell" ascii wide nocase
        $exec2 = "WScript.Shell" ascii wide nocase
        $exec3 = "Shell(" ascii wide nocase
        $net1 = "DownloadString" ascii wide nocase
        $net2 = "System.Net.WebClient" ascii wide nocase
        $net3 = "Invoke-WebRequest" ascii wide nocase
        $stealth1 = "WindowStyle Hidden" ascii wide nocase
        $stealth2 = "vbHide" ascii wide nocase
        $tool1 = "powercat" ascii wide nocase

    condition:
        1 of ($auto*) and 3 of ($exec*, $net*, $stealth*, $tool*)
}
