rule Generic_Ransomware_Note
{
    meta:
        description = "Detects common ransom note markers and decryption instructions"
        author = "Sentinel Defense"
        threat_level = "Critical"
    strings:
        $s1 = "Your files have been encrypted" nocase
        $s2 = "All your documents, photos, databases" nocase
        $s3 = "pay bitcoin to the following address" nocase
        $s4 = "send bitcoin" nocase
        $s5 = "Tor browser" nocase
        $s6 = ".onion" nocase
        $s7 = "private key will be destroyed" nocase
        $s8 = "decrypt your files" nocase
    condition:
        3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8)
}
