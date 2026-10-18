# Acquisition Notes — IR-2026-0414-01

**Acquirer:** Mike Torres (Network Engineer)
**Date:** 2026-04-14
**Context:** On-call escalation from SOC. James Chen asked me to pull memory and disk off WST-WS-031 and memory off WST-WS-017 while he handled containment.

---

## WST-WS-031

**Memory (wst-ws-031.mem)**

- Pulled with WinPmem (v3.3-rc3). Ran from a USB stick.
- Time of capture: 03:02Z. Host was still live, still beaconing.
- Destination: plugged into my workstation over USB3 to an external NVMe enclosure, then copied to `\\evidence\share\IR-2026-0414-01\`.
- I did not SHA-256 the file. Didn't think of it in the moment. Noted for next time.

**Disk (wst-ws-031.dd)**

- Acquired with FTK Imager, raw/dd format.
- Time of capture: started 04:51Z, finished 06:14Z. By that point James had already VLAN-isolated the host to 999.
- While preparing the image I mounted the live filesystem read-write to double-check whether `update.xml` was still present at the path the alert called out. It was. I was going to make a copy before imaging, but James told me to just pull the full image, which I did. I did not unmount or remount read-only before the FTK run.
- I did not SHA-256 this one either.

---

## WST-WS-017

**Memory (wst-ws-017.mem)**

- Pulled with WinPmem from the console at West Campus after James extended the scope. Capture at 03:38Z.
- Same workflow as WST-WS-031. Copied to the evidence share.
- No SHA-256 computed.

---

## Items I know are gaps

- No hashes at acquisition.
- I did not write a chain of custody form. I figured the SOC would do it after.
- The disk image was mounted read-write once. I understand this is bad. I did not write to any files but I opened Explorer on the mount, which may have changed access times.
- I did not record who had physical or network access to the artifacts between acquisition and hand-off to the SOC evidence share.

Handing this to the forensic analyst now. Helena has placed a litigation hold (ref LH-2026-0414-01) as of about 07:30Z. The analyst should treat all three artifacts as needing baseline hashes established at first access and full CoC from that point on.

— Mike Torres, 2026-04-14T07:42Z
