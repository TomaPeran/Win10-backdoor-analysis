rule Generic_Small_ReverseShell_WinSock_Persist
{
    meta:
        description = "Small PE: WinSock client + popen exec + Run key persistence + console hiding"
        mitre_attck = "T1059.003, T1547.001, T1564.003, T1095"
        confidence  = "medium (provjeri lazne pozitive)"

    strings:
        $ws1   = "WSAStartup" ascii
        $ws2   = "connect" ascii
        $ws3   = "recv" ascii
        $ws4   = "send" ascii

        $hide1 = "FindWindowA" ascii
        $hide2 = "ShowWindow" ascii

        $reg1  = "RegSetValueEx" ascii
        $reg2  = "RegSetKeyValue" ascii
        $reg3  = "RegCreateKeyEx" ascii
        $reg4  = "RegOpenKeyEx" ascii

        $run   = "CurrentVersion\\Run" ascii wide nocase
        $exec  = "popen" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $ws1 and 2 of ($ws*) and
        1 of ($hide*) and
        1 of ($reg*) and
        $run and $exec
}
