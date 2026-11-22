## Overview

This repository demonstrates principles and methodologies behind common Windows 10 backdoor techniques. It provides educational examples to understand how backdoors can be implemented, maintained, and hidden within the Windows operating system. This project is part of my learning path to enhance my malware analysis skills and deepen my cybersecurity knowledge.

Note: This code is intended only for educational purposes and should not be used for any unauthorized or illegal activities. Ensure that you have appropriate permissions when testing or using this code.

> **⚠️ Safety warning**
> `make compile` builds a working backdoor (a remote shell with registry persistence). Only build and run it inside an **isolated lab**: a disposable VM with a snapshot, a host-only or internal network (no internet), and no shared folders or clipboard. Never run it on your main machine or on systems you do not own. The detection tooling (`yara`, `check`, `sigma`) only analyses files and rules and is safe to run anywhere.

## Repository structure

```
.
├── Makefile                 # build, scan and convert targets
├── README.md
├── REPORT.md                # analysis report (architecture, MITRE ATT&CK, IOCs)
├── Win10_backdoor/
│   ├── backdoor.c           # client (implant)
│   └── server.c             # server (controller)
├── rules/
│   ├── yara/                # file / memory detection rules
│   │   ├── win10_backdoor_client.yar
│   │   ├── generic_reverse_shell.yar
│   │   └── win10_backdoor_server.yar
│   └── sigma/               # behavioural (log-based) detection rules
│       ├── b1_run_key_persistence.yml
│       ├── b2_port_50005.yml
│       ├── b3_internal_high_port.yml
│       ├── b4_b5_combined.yml
│       └── b6_discovery.yml
├── samples/                 # built binaries and hashes (generated)
└── results/                 # YARA hits and converted SIEM queries (generated)
```

## Client-side shell communication
This code implements a Windows-based client that establishes a connection to a remote server for local testing purposes. It provides basic remote shell functionality, such as executing commands and maintaining persistence by adding the program to the Windows startup registry.

### Features:
- Remote Shell Access: The program connects to a remote server, allowing it to receive commands and execute them on the local machine.
- Command Handling: Supports basic commands like q (quit), cd (change directory), and persist (add the program to the Windows startup registry for persistence).
- Persistence: The persist command adds the program to the Windows registry, making it run automatically on startup.
- Stealth Mode: The program runs hidden from the user by minimizing the console window upon launch.

### Way of working:
- Socket Connection: The program establishes a TCP connection to the server using the specified IP (192.168.1.175) and port (50005).
- Command Handling: executes known/custom commands (q, cd <path>, persist) as defined and other commands are executed on the local machine via popen and returns the output to the server.
- Console Stealth: The program runs without a visible console window using FindWindowA to hide it from the user.

## Server-side shell communication
This TCP server allows basic communication with a client through a shell-like interface.
### Features:
- TCP Socket Setup: Server listens on IP 192.168.1.175 and port 50005.
- Interactive Shell: Commands are read from the terminal and sent to the client.
- Command Handling: Supports q (quit), cd (placeholder for future functionality), and persist (send predefined response to client).
- Data Exchange: Server sends commands to the client and prints the response.

### Way of working:
- Socket: Creates a socket, binds to an IP and port, and listens for client connections.
- Command Loop: Waits for user input, sends commands to the client, and prints the client’s response.

## Prerequisites
- mingw-w64

Additional requirements for the analysis part of this repository:

| Tool | Used for | Install (Debian/Ubuntu/Parrot) |
|---|---|---|
| `make` | running the targets below | `sudo apt install make` |
| `mingw-w64` | cross-compiling the Windows client | `sudo apt install mingw-w64` |
| `yara` | scanning samples with the YARA rules | `sudo apt install yara` |
| Python 3 + `venv` | isolated environment for the Sigma tooling | `sudo apt install python3 python3-venv` |

The Sigma tooling (`sigma-cli`, the Sysmon pipeline and the Splunk/Elasticsearch backends) is installed **inside a virtual environment** (`myvenv/`) by `make venv`. Sigma plugins are installed per Python environment, so a global `sigma-cli` without the plugins will fail with `The pipeline 'sysmon' was not found`. Always use the Makefile targets, or activate the venv first (`source myvenv/bin/activate`).

## Installation
```
cd Win10-backdoor
make
```

Running `make` with no target runs `compile`, `yara` and `sigma` in order. Because `compile` builds the backdoor, read the safety warning above first. To only set up the analysis tooling without building anything, run `make venv`.

## Usage

All common tasks are Makefile targets:

| Command | What it does |
|---|---|
| `make help` | list all targets |
| `make venv` | create `myvenv/` and install `sigma-cli` and the plugins |
| `make compile` | build `samples/malware.exe` and `samples/server`, then write SHA-256 hashes (**lab only**) |
| `make yara` | scan `samples/` with all rules in `rules/yara/`, output saved to `results/yara_hits.txt` |
| `make check` | validate the syntax of all Sigma rules |
| `make sigma` | run `check`, then convert the rules to SIEM queries in `results/<backend>_queries.txt` |
| `make clean` | delete the built binaries and hashes |
| `make clean-venv` | delete `myvenv/` |
| `make clean-all` | `clean` + `clean-venv` + delete `results/` |

The Sigma conversion backend and pipeline can be overridden:

```
make sigma                          # Splunk + Sysmon pipeline (default)
make sigma BACKEND=elasticsearch    # Elasticsearch query output
```

Running the Sigma tooling manually:

```
source myvenv/bin/activate
sigma check rules/sigma/
sigma convert -t splunk -p sysmon rules/sigma/
```

## Detection

This repository also approaches the project from the defensive side: instead of only building the backdoor, it ships detection content for its artifacts and behaviour.

### YARA (file and memory)

| Rule | Purpose | Robustness |
|---|---|---|
| `Win10_Backdoor_Repo_Client` | Matches the default client build (hardcoded IP, Run key, `persist`, window-hiding API) | High precision, breaks if the config is changed |
| `Generic_Small_ReverseShell_WinSock_Persist` | Matches the general capability combination: WinSock client, `popen`, Run key persistence, console hiding | More resilient, may need false-positive tuning |
| `Win10_Backdoor_Repo_Server` | Matches the controller component | Medium |

### Sigma (behaviour, Sysmon-based)

| Rule | Detects | MITRE ATT&CK |
|---|---|---|
| B.1 `b1_run_key_persistence` | Run key written by a process in a user-writable path | T1547.001 |
| B.2 `b2_port_50005` | Outbound TCP to the default C2 port | T1571, T1095 |
| B.3 `b3_internal_high_port` | Unsigned user-path process connecting to an internal host on a high port (hunting) | T1571 |
| B.4 `b4_b5_combined` | `cmd.exe /c` spawned by a user-path parent (the `popen` pattern) | T1059.003 |
| B.5 `b4_b5_combined` | Burst of B.4 matches from one parent (correlation rule) | T1059.003 |
| B.6 `b6_discovery` | Discovery commands run through `cmd` (low confidence, enrichment only) | T1033, T1082, T1016 |

B.5 is a Sigma correlation rule and requires a recent `pysigma`. The venv created by `make venv` provides it. Not every backend supports correlations.

### What the rules cannot see

- Console hiding through `FindWindowA` / `ShowWindow` is an API call, not a log event. It is covered only by the YARA import and string checks or by EDR API telemetry.
- Command output returned over the socket is unencrypted. A network IDS (Zeek, Suricata) can match shell-like output on non-standard ports.

## Lab workflow

1. Create a Windows 10 VM, take a clean **snapshot**, and set the network to host-only or internal.
2. Install Sysmon with a configuration that logs process creation (ID 1), network connections (ID 3) and registry value sets (ID 12/13).
3. Build the samples on the analysis machine with `make compile` and copy them into the VM. Defender will probably quarantine them, which is useful data for the report. Add an exclusion **inside the VM only**.
4. Because the IP is hardcoded, give the server and client VMs the matching addresses (`192.168.1.175` for the server) or change the value in the source and rebuild.
5. From the server, send `persist`, `cd` and a few ordinary commands. Export the Sysmon log and check which Sigma rules would fire.
6. **Revert the snapshot** afterwards. The `persist` command leaves a value in the Run key.
7. Run `make yara` against the samples, and against a clean corpus of legitimate programs to measure false positives.
8. Robustness test: change the IP, port and command names, rebuild, and rescan. The specific rules should stop matching while the generic and behavioural rules keep firing.

To validate the persistence rule without any malware, use the Atomic Red Team test for T1547.001.

## Improvements
The following are ideas for improving the functionality, security, and compatibility of the backdoor project. While Microsoft Defender provides strong built-in protection for Windows 10 systems, these enhancements aim to ensure that the backdoor is more robust, stealthy, and compatible across various environments.
- [ ] **Handle Exiting Signals:** Implement handling for signals that would allow the program to gracefully exit. In your current code, you are manually closing the socket and calling WSACleanup() when the "q" command is received, which ends the program.
- [ ] **Every Second Command Gets Executed:** An issue has been noticed where sometimes every other command doesn't get executed. This is likely due to internal issues like bad network traffic or timing problems, but it's better to check it out to be sure.
- [ ] **Make Program Compatible with Linux-based OS:** Currently, the backdoor is Windows-centric, relying heavily on Windows-specific libraries (like WinSock and Windows API). The goal is to make the program compatible with Linux-type operating systems
- [ ] **Check for Memory Leaks:** While the backdoor is functional, it's important to ensure that all dynamically allocated memory is freed properly to avoid memory leaks
- [ ] **Exchange `strcmp` with `strncmp`:** The program currently uses `strcmp` for string comparison. This can be a potential security risk, as `strcmp` does not prevent buffer overflow issues. Replacing `strcmp` with `strncmp` will limit the number of characters compared, providing a safer and more controlled string comparison.
- [ ] **Add an Enum and a Switch to Handle Commands:** To improve the readability and scalability of the code, we can define an enum to represent different commands. Using a switch statement to check for commands would make the code more modular, easier to extend, and easier to maintain.

### Detection engineering roadmap
- [ ] Add a Suricata rule for the unencrypted shell traffic on the network layer.
- [ ] Add a Chainsaw workflow to run the Sigma rules directly against exported Sysmon `.evtx` logs.
- [ ] Pin the Sigma tooling versions in a `requirements.txt` for a reproducible environment.
- [ ] Measure false positives against a clean Windows corpus and record the results in `results/`.

## Legal and ethical use

This project exists for education and defensive research. Build, run and test it only on systems you own or have explicit written permission to test, and only in an isolated environment. Do not upload the compiled binaries to public scanning services without considering that submitted samples are shared. Keep the samples in a password-protected archive or an excluded folder when not in use.
