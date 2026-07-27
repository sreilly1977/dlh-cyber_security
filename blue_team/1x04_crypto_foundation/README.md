# [0. The Crypto Inventory](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/0-crypto_inventory.md)

## Goal
Map every data flow at MedDefense against its current cryptographic protection state, exposing every gap in one document.

## Context
Before you can fix MedDefense's cryptographic posture, you need to see the full picture in one place. The vulnerability findings from 1x02 identified individual crypto weaknesses (TLS 1.0 on the portal, unencrypted backups, cleartext DICOM). The risk register in 1x03 tracked some of these as risks. But nobody has produced a systematic inventory that maps every category of data, in every state, to its current level of protection.

This is the document that makes the invisible visible. When you finish, every cell where it says "None" is a gap that the rest of this project will address.

### Provided Files
`meddefense-crypto-audit-notes.txt`

## Instructions
Produce a **Data Protection Map** for MedDefense. The map is a matrix that crosses data categories (rows) with data states (columns).

### Columns (Data States):

1. **At Rest** (stored on disk, database, NAS, backup)
2. **In Transit** (moving between systems over the network)
3. **In Use** (actively being processed or displayed)

### Rows (Data Categories): Use at minimum these 7:

1. Patient medical records (EHR data in PostgreSQL)
2. Financial/billing data (MySQL on billing-srv-01)
3. Medical images (DICOM on PACS)
4. Credentials (Active Directory, application passwords)
5. Backup data (NAS-01)
6. Email (O365)
7. VPN traffic (site-to-site tunnels)

For each cell, document:

```
Protection: [Algorithm/Protocol used, or "None"]
Evidence: [Reference to 1x02 finding, 1x00 observation, or audit notes]
Status: [Adequate / Weak / Absent]
```

After the matrix, produce a **Gap Summary:** How many of the 21 cells (7 × 3) have adequate protection? How many are weak? How many are absent? What is the overall crypto coverage percentage?

---
