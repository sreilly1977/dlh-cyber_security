# Mock Validation API (Task 7)

This directory is served by a static HTTP server as a stand-in for the real
MedDefense endpoint/SIEM/service APIs your `recovery_validation.sh` must query.

## Run

```
cd mock_validation_api
python3 -m http.server 8080 --bind 127.0.0.1
```

## Endpoints exposed by the filesystem

| HTTP path | Returns |
|---|---|
| `/endpoint/processtree/WST-WS-031` | `endpoint/processtree/WST-WS-031.json` |
| `/endpoint/processtree/WST-WS-017` | `endpoint/processtree/WST-WS-017.json` |
| `/endpoint/processtree/LIS-WSIDE-01` | `endpoint/processtree/LIS-WSIDE-01.json` |
| `/endpoint/persistence/WST-WS-031` | `endpoint/persistence/WST-WS-031.json` |
| `/endpoint/persistence/WST-WS-017` | `endpoint/persistence/WST-WS-017.json` |
| `/endpoint/persistence/LIS-WSIDE-01` | `endpoint/persistence/LIS-WSIDE-01.json` |
| `/siem/netflow` | `siem/netflow.json` (24h window, includes zeroes for both bad IPs) |
| `/siem/detection/wz-edr-100041` | `siem/detection/wz-edr-100041.json` |
| `/siem/detection/wz-edr-100041/synthetic` | `siem/detection/wz-edr-100041/synthetic.json` |
| `/service/epic-api/health` | `service/epic-api/health` (200 OK; plain-text body) |
| `/service/lis-api/health` | `service/lis-api/health` (200 OK; plain-text body) |

## Contract (for your script)

- Every JSON endpoint returns `{"status": "ok", "data": {...}}` on success.
- `/service/*/health` returns HTTP 200 with body `OK` — your script uses `curl -w '%{http_code}'` or `jq` as it prefers.
- All clean-state data in this directory represents the environment AFTER successful containment and eradication. Your script should therefore report `PASS` on every check when pointed at this server.

## Flipping to a failure case for self-testing

Each endpoint ships with a `.fail` sibling (e.g. `siem/netflow.fail.json`).
To simulate a failure, `cp siem/netflow.fail.json siem/netflow.json` and re-run.
