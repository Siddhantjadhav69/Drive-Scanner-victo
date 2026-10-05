rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Detects obfuscated PowerShell download cradles and bypasses"
        author = "Sentinel Defense"
        threat_level = "High"
    strings:
        $bypass1 = "Set-ExecutionPolicy Bypass" nocase
        $bypass2 = "-ExecutionPolicy Unrestricted" nocase
        $down1 = "DownloadString(" nocase
        $down2 = "DownloadFile(" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $webclient = "Net.WebClient" nocase
        $invoke_exp = "Invoke-Expression" nocase
        $iex = "iex(" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        ($hidden and ($enc1 or $enc2)) or
        ($webclient and ($down1 or $down2) and ($invoke_exp or $iex)) or
        ($bypass1 and $bypass2 and $enc1)
}
