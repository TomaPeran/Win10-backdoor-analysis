rule Win10_Backdoor_Repo_Server
{
    meta:
        description = "Controller component of the Win10-backdoor educational repo"
        confidence  = "medium"

    strings:
        $ip      = "192.168.1.175" ascii
        $bind    = "bind" ascii fullword
        $listen  = "listen" ascii fullword
        $accept  = "accept" ascii fullword
        $persist = "persist" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $ip and
        all of ($bind, $listen, $accept) and
        $persist
}
