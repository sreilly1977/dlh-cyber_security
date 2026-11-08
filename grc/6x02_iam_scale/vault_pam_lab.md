# MedDefense Vault PAM Lab

Evidence-based analysis of the HashiCorp Vault database secrets engine as a
replacement for static service account credentials, using
`svc_epic_int` as the motivating case. Source evidence:
`vault_database_secrets_transcript.md`, `vault_lease_revoke_transcript.md`,
`svc_epic_int_static_account_risk.md`, `pam_migration_candidates.csv`.

## Lab Evidence Summary

The lab demonstrates the database secrets engine configured against the
MedDefense LIS MySQL database (`meddefense-lis`):

- Engine enabled at `database/`.
- Connection configured with the `mysql-database-plugin`, bound to
  `allowed_roles="lis-readonly,lis-readwrite"` and a dedicated
  `vault_manager` bootstrap user.
- Two roles defined: `lis-readonly` (default TTL 1h, max TTL 4h) and
  `lis-readwrite` (default TTL 15m, max TTL 1h).

Every credential issued by these roles is generated per request, unique,
time-bounded by a lease, and revocable at the database. This contrasts
directly with `svc_epic_int`: a static service account holding Domain
Admins, last logged in 1,156 days ago, described as having no current
function, whose password had not changed in three years and was stored in
a configuration file.

## Dynamic Credential Demonstration

Two credentials were issued from the same database under different roles.

Read-only request (`vault read database/creds/lis-readonly`):

- Lease ID: `database/creds/lis-readonly/3s9fXJd7aMedDefense001`
- Username: `v-lis-readonly-H7s9k2`
- Password: unique generated value (shown in transcript)
- Lease duration: `1h`, renewable, max TTL `4h`

Verification against the database confirmed least privilege at the SQL
layer, not just the Vault layer:

~~~text
USER(): v-lis-readonly-H7s9k2@10.0.3.5
GRANT SELECT ON `lis_production`.* TO 'v-lis-readonly-H7s9k2'@'%'
~~~

The account exists only as `GRANT SELECT` on the production LIS schema. It
cannot write, drop or alter anything.

Read-write request (`vault read database/creds/lis-readwrite`):

- Lease ID: `database/creds/lis-readwrite/9kLmVaultRw002`
- Username: `v-lis-readwrite-Q2p8`
- Password: unique generated value (shown in transcript)
- Lease duration: `15m`, renewable, max TTL `1h`

Note the role-to-TTL relationship: the read-write role, which can mutate
production data, carries the shortest lifetime (15 minutes default, 1 hour
ceiling), while the read-only role earns a longer window (1 hour default,
4 hours ceiling). Risk scales inversely with TTL.

`vault list sys/leases/lookup/database/creds/lis-readonly/` confirms Vault
is tracking the active lease, so every issued credential is enumerable by
the security team in real time.

## Lease and TTL Evidence

A lease is Vault's record that a credential exists and its remaining
lifetime. The evidence shows:

- Every credential issuance creates a lease ID unique to that credential
  (e.g. `3s9fXJd7aMedDefense001` for the read-only credential).
- `lease_duration` is enforced per role: 1h for `lis-readonly`, 15m for
  `lis-readwrite`.
- Leases are renewable within the role's `max_ttl`, so an application can
  extend a session without ever holding a long-lived secret.
- `vault list sys/leases/lookup/...` exposes all live credentials, giving a
  real-time inventory of database access, something impossible with static
  accounts scattered through configuration files.

When a lease expires, Vault revokes the credential at the database
automatically. The application either requests a fresh credential or loses
access; there is no unmanaged standing password to outlive its purpose.

## Revocation Evidence

Manual revocation of the read-write credential:

~~~text
$ vault lease revoke database/creds/lis-readwrite/9kLmVaultRw002
All revocation operations queued successfully!
~~~

The database immediately rejects the credential:

~~~text
$ mysql -uv-lis-readwrite-Q2p8 -p... lis_production -e "SELECT USER();"
ERROR 1045 (28000): Access denied for user 'v-lis-readwrite-Q2p8'@'10.0.3.5' (using password: YES)
~~~

Root-level inspection of `mysql.user` for `v-lis%` accounts returns only
the still-valid read-only user, confirming the revoked read-write user was
removed from the database entirely, not merely locked:

~~~text
+-----------------------+------+
| v-lis-readonly-H7s9k2 | %    |
+-----------------------+------+
~~~

A stolen username/password is useless after revocation: the credential no
longer exists as far as the database is concerned.

## Static vs Dynamic Credential Comparison

The comparison is drawn from the `svc_epic_int` risk evidence and the Vault
transcripts.

| Dimension | Static (svc_epic_int) | Dynamic (Vault database engine) |
|---|---|---|
| Credential lifetime | Indefinite; password unchanged for 3+ years, valid until manually rotated (never was) | 15m to 1h per lease depending on role, capped by max TTL; invalid the moment the lease expires |
| Rotation method | Manual password change by an administrator, dependent on someone remembering; none occurred | Automatic and continuous; every issuance generates a new unique credential, so rotation happens on every use |
| Blast radius if stolen | Total: a Domain Admin account usable indefinitely, extracted from memory and used for 3 hours before detection, matching the incident path | Minimal: credential valid only until TTL expiry, scoped to a single database and read or read-write role; attacker must re-compromise Vault to obtain a new one |
| Audit trail | None inherent; a shared static password cannot attribute use to an actor or session | Full: every issuance is a logged Vault request with a distinct username, and every live lease is enumerable via the leases API |
| Off-boarding | Must find and disable every static account across systems; svc_epic_int survived with no identified function for 3 years | Applications authenticate to Vault via tightly controlled auth methods; removing a policy or token revokes all derived credentials instantly, and unused roles simply stop issuing leases |

The architectural difference is that the static model persists a secret,
while the dynamic model mints one on demand and destroys it on schedule.
There is no equivalent of svc_epic_int to steal in the Vault model because
no such credential exists between requests.

## Migration Recommendation

Ranked against `pam_migration_candidates.csv`:

1. **`svc_epic_int` — migrate immediately (Critical).** No current function
   identified, 1,156 days dormant, Domain Admins. The correct outcome is
   decommissioning, not migration: confirm no dependency, disable and remove
   the account. Its hypothetical workload, if one resurfaces, should consume
   a Vault-issued scoped role, never a standing Domain Admin credential.
2. **`svc_helpdesk` — migrate immediately (Critical).** Vendor-granted
   Domain Admins exceeding ticket-routing needs. Rebuild the automation to
   request a short-TTL, least-privilege credential at runtime.
3. **`svc_backup` — migrate (High).** Nightly backup needs broad data
   access but not standing Domain Admins. Issue a scoped database or storage
   credential on a schedule aligned with the backup window, revoking at job
   completion.
4. **`svc_monitoring` and `svc_av_mgmt` — migrate (Medium).** Both are
   active (last login 0 days) so migration requires coordination. Move
   monitoring to read-only scoped credentials and evaluate endpoint
   management for a JIT-scoped role per the candidate list.

General pattern for each migration: inventory the workload behind the
account, define a Vault role with the minimum permissions and shortest
acceptable TTL, convert the application to fetch credentials from Vault at
startup or per session, verify lease behaviour under load, then disable and
delete the static account. The success measure mirrors the lab evidence:
zero standing privileged service account passwords, every live credential
enumerable as a lease, and every credential provably dead after its TTL or
an operator-issued `vault lease revoke`.
