rule Win10_Backdoor_Repo_Client
{
    meta:
        description = "Client implant from the Win10-backdoor educational repo (default build)"
        mitre_attck = "T1547.001, T1059.003, T1564.003, T1571"
        confidence  = "high (default config only)"

    strings:
        $c2_ip       = "192.168.1.175" ascii wide
        $run_key     = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $cmd_persist = "persist" ascii fullword
        $cmd_cd      = "cd " ascii
        $api_find    = "FindWindowA" ascii
        $api_show    = "ShowWindow" ascii
        $api_wsa     = "WSAStartup" ascii
        $api_popen   = "popen" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $c2_ip and
        $run_key and
        ( $cmd_persist or $cmd_cd ) and
        2 of ($api_*)
}
