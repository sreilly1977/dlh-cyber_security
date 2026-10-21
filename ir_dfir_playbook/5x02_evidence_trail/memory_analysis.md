# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

**Case:** LH-2026-0414-01 / IR-2026-0414-01
**Analyst:** Steve — Cybersecurity Engineer
**Date of analysis:** 2026-10-21

## Artifact verification

- ART-002 (wst-ws-031.mem) hash at analysis start: `8144ca9ee538268599e65104a9901d462d550064d5263f2bf4fa1f7f43e1176e`
  (matches baseline in hashes.txt; `[PASS]` per `verify_artifacts.sh`)
- ART-003 (wst-ws-017.mem) hash at analysis start: `a675bea9188f5a9b2d8829af15153dee714103b01afd87b5c6df4f7dfd8b0300`
  (matches baseline in hashes.txt; `[PASS]` per `verify_artifacts.sh`)
- Acquisition: ART-002 captured 2026-04-14T03:02:00Z, host live and still beaconing, pre-isolation;
  ART-003 captured 2026-04-14T03:38:00Z from console at West Campus (per chain of custody)
- CoC entries updated: yes

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| ⟨timestamp⟩ | Steve | ART-002 | memory_analysis | Volatility 3 | yes | Baseline 8144ca... verified pre-analysis; read-only analysis of dump |
| ⟨timestamp⟩ | Steve | ART-003 | memory_analysis | Volatility 3 | yes | Baseline a675be... verified pre-analysis; read-only analysis of dump |

**Method note:** SIEM evidence is treated as investigative context only; all conclusions below
derive from Volatility 3 findings. Plugin order follows the order of volatility of the
information sought (processes → network → code → credentials).

## wst-ws-031.mem findings

### ART-002-M01: Suspicious process tree

```
$ vol -f wst-ws-031.mem windows.pstree.PsTree
PID  PPID  Name             ...
4120   --   explorer.exe
 * 7812 4120 powershell.exe   (cmd: powershell.exe -ep bypass -w hidden -enc JABzAD0AIgBoAHQAdABwAHMAOg...)
   * 8104 7812 MSBuild.exe    (cmd: msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml)
```

- PIDs involved: 4120 (explorer), 7812 (powershell), 8104 (MSBuild)
- Start times: ⟨from windows.pslist.PsList output — record create time for PIDs 7812 and 8104⟩
- Significance: powershell.exe is the direct parent of MSBuild.exe, and the PowerShell
  command line carries `-ep bypass -w hidden -enc` (execution-policy bypass, hidden window,
  encoded command). A stock Windows developer utility (MSBuild) compiling a file in the
  user's Temp directory, spawned by an encoded PowerShell run, is anomalous on its face.
  User-context execution as MEDDEFENSE\dmarsh.
- ATT&CK: T1059.001 (PowerShell) and T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
- Certainty: **confirmed** (process tree present in memory at capture)

### ART-002-M02: Live C2 connection at time of capture

```
$ vol -f wst-ws-031.mem windows.netscan.NetScan
TCP  10.42.118.31:49722  185.220.101.47:443  ESTABLISHED  PID 8104  MSBuild.exe
```

- PID involved: 8104 (MSBuild.exe)
- Significance: An active, established outbound TCP connection to 185.220.101.47:443 owned
  by MSBuild.exe at the moment of capture. Legitimate MSBuild activity does not originate
  sustained outbound TLS connections from a clinical workstation. The destination is a Tor
  exit relay, meaning the C2 channel rides an anonymizer overlay — consistent with the C2
  address also appearing in strings on disk (cross-reference ART-001-F05, disk analysis).
- ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols) / T1090.003 (Proxy: Multi-hop
  Proxy, Tor)
- Certainty: **confirmed**

### ART-002-M03: Strings corroboration

```
$ strings wst-ws-031.mem | grep -E "login-verification|185\.220|WebClient"
https://ms0365-support.login-verification.click/auth
185.220.101.47
update.xml / Inline MSBuild task / System.Net.WebClient
```

- Significance: The phishing URL, the C2 IP, and the payload name coexist in physical
  memory, tying the initial-access vector, the C2 channel, and the executed payload to the
  same compromised session. `System.Net.WebClient` indicates managed-code download
  primitives were resident.
- ATT&CK: supporting evidence for T1566.002 / T1071.001
- Certainty: **confirmed** (presence in memory); attribution of each string to a specific
  process is not asserted without VAD-to-process mapping.

### ART-002-M04: DLLs loaded by msbuild.exe

```
$ vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104
⟨paste DllList output from your run⟩
```

- PIDs involved: 8104
- Significance: Expected anomalies to evaluate: presence of `System.Net.Http.dll` /
  `System.Net.WebClient`-related assemblies in a process whose legitimate build workload
  (on a clinical workstation with no developer role) should not load networking stacks;
  any unsigned or non-standard-path DLLs. ⟨Record the finding and interpretation from the
  actual output.⟩
- ATT&CK: T1127.001 supporting evidence
- Certainty: ⟨pending run — tag from actual output⟩

### ART-002-M05: Injected executable memory in msbuild.exe

```
$ vol -f wst-ws-031.mem windows.malfind.Malfind
⟨paste Malfind output; expected shape per case materials: an executable anonymous VAD inside
MSBuild.exe with an MZ/PE header at page-aligned start⟩
```

- PID involved: 8104 (and any other PIDs Malfind flags — record them)
- Significance: A VAD with PAGE_EXECUTE_READWRITE protection containing an MZ header inside
  a signed Microsoft binary indicates code injected into a trusted process — the inline
  task's compiled payload resident in memory. This is evidence that cannot survive on
  disk, which is precisely why this memory capture was necessary.
- ATT&CK: T1055 (Process Injection)
- Certainty: ⟨pending run — tag from actual output; if the MZ/VadS region is present in
  PID 8104, confirmed⟩

### ART-002-M06: Handles held by lsass.exe

```
$ vol -f wst-ws-031.mem windows.handles.Handles --pid ⟨lsass_pid⟩
⟨paste output; the lsass PID comes from windows.pslist.PsList⟩
```

- PID involved: ⟨lsass PID⟩
- Significance: Handle review of lsass at capture time: look for handles into remote
  process address spaces, logon-session tokens for dmarsh (and any unexpected interactive
  sessions), and LSASS-opened thread/process handles consistent with credential dumping.
  ⟨Record the finding and interpretation from the actual output.⟩
- ATT&CK: T1003.001 (LSASS Memory) supporting evidence
- Certainty: ⟨pending run⟩

### ART-002-M07: Credential material extraction attempt

```
$ vol -f wst-ws-031.mem windows.hashdump.Hashdump
⟨paste output from your run⟩
```

- Significance: Documents what credential material was resident (NTLM hashes / LSA
  secrets) at capture — establishing what the attacker could have harvested from this
  host. Expected per case materials: NTLM hash material for dmarsh present in LSASS at
  capture. Handle the output per evidence-handling policy: hash values are secrets and
  must not be reproduced verbatim in this report beyond what is necessary; store securely
  and reference by evidence ID.
- ATT&CK: T1003.001 (Credentials from LSASS Memory)
- Certainty: ⟨pending run — tag from actual output⟩

## wst-ws-017.mem findings

*(Captured 2026-04-14T03:38Z, West Campus, before host isolation. Host identity and the
existence of a second C2 channel were known to be at issue; the Volatility findings below
stand on their own, with SIEM context used only for triage orientation.)*

### ART-003-M01: Process list

```
$ vol -f wst-ws-017.mem windows.pslist.PsList
⟨paste output — evaluate for: MSBuild.exe, powershell.exe, unexpected user-context
processes, processes running as MEDDEFENSE\dmarsh via network logon (type 3)⟩
```

- Certainty: ⟨pending run⟩

### ART-003-M02: Process tree

```
$ vol -f wst-ws-017.mem windows.pstree.PsTree
⟨paste output — expected evaluation: whether MSBuild.exe on this host is parented by
powershell.exe, mirroring the chain on WST-WS-031⟩
```

- Certainty: ⟨pending run⟩

### ART-003-M03: Command lines

```
$ vol -f wst-ws-017.mem windows.cmdline.CmdLine
⟨paste output — evaluate for encoded PowerShell commands; decoded content may reference a
second C2 address⟩
```

- Certainty: ⟨pending run⟩

### ART-003-M04: Network connections

```
$ vol -f wst-ws-017.mem windows.netscan.NetScan
⟨paste output — evaluate for outbound TLS owned by MSBuild.exe or powershell.exe to a
destination distinct from 185.220.101.47⟩
```

- Significance: If MSBuild on WST-WS-017 holds an established connection to a different
  external endpoint, the two hosts were running parallel beacon channels — a second C2
  IP widens the IOC list and the perimeter-blocking scope.
- ATT&CK: T1071.001 / T1090.003
- Certainty: ⟨pending run⟩

## Consolidated memory findings

| Evidence ID | Host | Finding | ATT&CK | Certainty |
|---|---|---|---|---|
| ART-002-M01 | WST-WS-031 | PowerShell → MSBuild process tree, encoded hidden command | T1059.001 / T1127.001 | confirmed |
| ART-002-M02 | WST-WS-031 | Established TCP to 185.220.101.47:443 owned by MSBuild PID 8104 | T1071.001 / T1090.003 | confirmed |
| ART-002-M03 | WST-WS-031 | Phishing URL, C2 IP, payload name resident in memory | supporting | confirmed |
| ART-002-M04 | WST-WS-031 | DLL inventory of PID 8104 | T1127.001 | ⟨pending run⟩ |
| ART-002-M05 | WST-WS-031 | MZ-header executable VAD in MSBuild.exe | T1055 | ⟨pending run⟩ |
| ART-002-M06 | WST-WS-031 | LSASS handle review | T1003.001 | ⟨pending run⟩ |
| ART-002-M07 | WST-WS-031 | Hashdump credential material | T1003.001 | ⟨pending run⟩ |
| ART-003-M01…M04 | WST-WS-017 | Process/tree/cmdline/netscan review | T1550.003 / T1071.001 | ⟨pending run⟩ |

## Caveats

1. Memory captures are point-in-time: evidence of processes that terminated before
   03:02:00Z / 03:38:00Z respectively is limited to residual artifacts (pool allocations,
   freed VADs, strings). Absence in memory is not proof of absence.
2. Memory strings (M03) establish presence, not process attribution; correlation to a PID
   requires VAD mapping, which is where M05's output contributes.
3. SIEM alert context oriented the triage; every conclusion above rests on Volatility
   output, per the task's evidence hierarchy.
4. Hashdump output is credential material: minimize exposure, do not reproduce in full in
   any report outside the evidence store.
