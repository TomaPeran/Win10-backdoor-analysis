# Report: Analysis of the "Win10-backdoor" Repository

## 1. Summary
The repository contains an educational example of a simple Windows 10 backdoor written in C (mingw-w64), consisting of a client (implant) and a server (control side). The author describes it as part of their malware analysis learning path. According to the documentation, the functionality is very basic: a remote shell, registry persistence, and hiding the console window. The documentation also includes a list of planned "improvements", some of which are aimed at evading detection.

## 2. Architecture

| Component | Description |
|---|---|
| **Client** | Connects over TCP to the server (192.168.1.175:50005), receives commands, executes them locally via `popen`, and returns the output. |
| **Server** | Listens on the same address and port, reads commands from the terminal, sends them to the client, and prints the response. |

Communication is a simple command-response loop over the WinSock interface.

## 3. Functionality
- **Remote shell:** execution of arbitrary commands on the target machine.
- **Built-in commands:** `q` (quit), `cd <path>` (change directory), `persist` (persistence).
- **Persistence:** adding the program to the Windows startup registry.
- **Hiding:** concealing the console window using `FindWindowA`.

## 4. MITRE ATT&CK Mapping

| Behavior | Technique |
|---|---|
| Autostart via registry | T1547.001, Registry Run Keys / Startup Folder |
| Command execution via shell | T1059.003, Windows Command Shell |
| Communication on a non-standard port | T1571, Non-Standard Port |
| Hidden window | T1564.003, Hidden Window |
| C2 channel over TCP | T1095, Non-Application Layer Protocol |

## 5. Technical Assessment
**Weaknesses and limitations:**
- Communication is neither encrypted nor authenticated. Anyone who can connect to the port can take control.
- The IP address and port are hardcoded (a private LAN address), so the tool is practically suitable only for local testing.
- Persistence and hiding are trivial, well-known patterns that most security tools recognize.
- Known issues: every second command fails to execute (likely buffer/`recv` handling), possible memory leaks, no signal handling.
- The proposed `strcmp` → `strncmp` replacement is superficial. The real risk lies in buffer handling and unchecked command execution.

**Sophistication level:** low (learning/PoC level).

## 6. Indicators of Compromise (for defenders)
- An unknown process with an outbound TCP connection to an internal address on port 50005.
- A new or unfamiliar value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (or the `HKLM` equivalent).
- A process spawning `cmd.exe` as a child (launched via `popen`) with no visible user interface.
- An executable that calls `FindWindowA` / `ShowWindow` on its own console window immediately after launch.

## 7. Detection and Mitigation
- **Detection:** monitor Run key changes (Sysmon event IDs 12/13, Autoruns), monitor unusual network connections (Sysmon ID 3), and use EDR rules for process chains (unknown exe → cmd.exe).
- **Mitigation:** application allowlisting (WDAC/AppLocker), port-based egress filtering, least privilege, and a regularly updated Defender/EDR.

## 8. Ethical and Legal Considerations
The author stresses the educational purpose and the need for authorization. Keep in mind that working with such tools is acceptable only in an isolated lab (VMs, separate network) and on systems you own. The "Improvements" section describing increased stealth and Defender evasion has no educational value for defense, so I would not recommend pursuing or developing it.

## 9. Conclusion
The project is a simple example of a reverse shell implant with persistence, useful for understanding the basic patterns a malware analyst needs to recognize. For learning, it is most valuable when approached from the defensive side: analyzing the binary, writing detection rules (YARA/Sigma), and tracing its artifacts in a lab environment.
