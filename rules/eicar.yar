rule eicar_basic
{
    meta:
        description = "Standard EICAR test file to verify AV functionality"
        author = "Claude"
    strings:
        $eicar_string = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar_string
}
