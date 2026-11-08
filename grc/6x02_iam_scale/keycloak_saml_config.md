# MedDefense SAML SSO Configuration Reference

Documented reference for the SAML 2.0 SSO integration between the Keycloak
identity provider (realm `meddefense`) and the service provider
`meddefense-portal`. Source evidence: Keycloak realm export, two captured
SAML responses (`d.walsh`, `r.kim`), SAML flow notes and the decoded
SAML response reference.

## Realm Configuration Summary

The `meddefense` realm is the authentication boundary for MedDefense Health
Systems workforce identities.

| Setting | Value | Security relevance |
|---|---|---|
| Realm | `meddefense` | Isolates MedDefense users and clients from other tenants |
| Display name | MedDefense Health Systems | Human-readable realm label |
| Enabled | `true` | Realm accepts authentication requests |
| SSO session idle timeout | `1800` seconds (30 minutes) | Idle browser sessions are invalidated after 30 minutes of inactivity, limiting session hijack windows |
| Brute force protected | `true` | Repeated failed logins trigger account lockout behaviour |
| Failure factor | `5` | Five failed attempts before brute force protection engages |

Centralizing authentication here means one login event per user per session
and one disable action during off-boarding, replacing per-system account
management across Epic, PACS, pharmacy and clinical communications.

## Client Configuration Summary

The service provider is registered as a SAML client in the realm.

| Setting | Value | Security relevance |
|---|---|---|
| Client ID | `meddefense-portal` | Matches the `Audience` value in issued assertions |
| Protocol | `saml` | SAML 2.0 web browser SSO profile |
| Redirect URIs | `http://localhost:5000/*` | Permitted SP endpoints in the lab environment |
| ACS URL | `http://localhost:5000/saml/acs` | Assertion Consumer Service; also the `Destination` of responses and `Recipient` of SubjectConfirmationData |
| NameID format | `email` (`saml_force_name_id_format: true`) | Assertion NameID is forced to the email format regardless of client request |
| Assertion signature | `saml.assertion.signature: true` | Assertions are digitally signed by the IdP |
| Server signature | `saml.server.signature: true` | The full SAML response document is also signed |

Both the assertion and the response document are signed, so an attacker
cannot modify the subject or role values, and unsigned responses are
rejected by the SP.

## Test Users and Role Attributes

Two users exist in the realm. Authorization is driven by the
`MedDefenseRole` user attribute, mapped into assertions by the
`saml-user-attribute-mapper` protocol mapper named `MedDefenseRole`
(attribute name `MedDefenseRole`, name format `Basic`).

| Username | Email | Enabled | MedDefenseRole |
|---|---|---|---|
| d.walsh | d.walsh@meddefense.internal | true | `clinical_staff` |
| r.kim | r.kim@meddefense.internal | true | `it_security` |

At the SP, `MedDefenseRole` maps to authorization: `clinical_staff` grants
clinical permissions, `it_security` grants IT security permissions. Because
the attribute originates from the IdP and the assertion is signed, the SP
can trust role values without maintaining its own role store.

## Annotated SAML Assertion: d.walsh

The captured response below is annotated element by element. Validation
behaviour is identical for the `r.kim` assertion; only the NameID,
session index and role attribute differ.

~~~xml
<samlp:Response ID="_resp-dwalsh-20260428" ... IssueInstant="2026-04-28T09:15:00Z"
                Destination="http://localhost:5000/saml/acs">
  <!-- Response wrapper: Destination must equal the SP's ACS URL, else reject -->

  <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>
  <!-- Issuer: identifies the IdP entity. SP must verify it matches the
       registered/known IdP for this client before trusting anything else. -->

  <ds:Signature>
    <ds:SignedInfo><ds:Reference URI="#_assert-dwalsh-001"/></ds:SignedInfo>
    <ds:SignatureValue>SIMULATED_SIGNATURE_VALUE_FOR_LAB_ONLY</ds:SignatureValue>
  </ds:Signature>
  <!-- Signature: XML digital signature over the referenced assertion.
       SP verifies the signature against the IdP's public key; an invalid
       signature means tampering and the response must be rejected. -->

  <saml:Assertion ID="_assert-dwalsh-001" Version="2.0" IssueInstant="2026-04-28T09:15:00Z">
    <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>
    <!-- Assertion-level Issuer: same IdP entity check as above. -->

    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        d.walsh@meddefense.internal
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-04-28T09:20:00Z"
                                      Recipient="http://localhost:5000/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <!-- NameID: authenticated user identity, email format, mapped to the
         local account at the SP. Recipient must match the ACS URL;
         NotOnOrAfter bounds the bearer confirmation window. -->

    <saml:Conditions NotBefore="2026-04-28T09:14:55Z"
                     NotOnOrAfter="2026-04-28T09:20:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>meddefense-portal</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <!-- Conditions: validity window and intended audience. SP rejects the
         assertion if current time is before NotBefore or at/after
         NotOnOrAfter, and if it is not the stated Audience. This prevents
         replay and assertion redirection to another SP. -->

    <saml:AuthnStatement AuthnInstant="2026-04-28T09:14:58Z"
                         SessionIndex="_session-dwalsh-001">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <!-- AuthnStatement: records the authentication event at the IdP,
         when it happened and under what context (password over a protected
         transport). SP uses it to establish its local session. -->

    <saml:AttributeStatement>
      <saml:Attribute Name="MedDefenseRole">
        <saml:AttributeValue>clinical_staff</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email">
        <saml:AttributeValue>d.walsh@meddefense.internal</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <!-- AttributeStatement: user attributes released by the IdP.
         MedDefenseRole drives authorization mapping at the SP; email
         correlates the assertion to the account record. -->
  </saml:Assertion>
</samlp:Response>
~~~

## Assertion Expiration and Replay Prevention

Every assertion carries an explicit validity window. `NotBefore` sets the
earliest instant at which the assertion may be accepted (here
09:14:55Z, slightly before the authentication event), and `NotOnOrAfter`
sets its expiry (09:20:00Z, five minutes after issuance, mirrored in the
bearer SubjectConfirmationData). An SP that checks these conditions rejects
an expired assertion, so a captured response cannot be replayed hours or
days later to mint a session. Replay resistance depends on enforcing this
window: expired assertions must be rejected, never accepted with a warning,
because acceptance converts a stolen or intercepted response into a valid
login. Combined with audience and recipient checks, which prevent the same
assertion being consumed by a different application, the time window is the
primary control bounding the useful life of a single authentication event.
Production deployments typically pair this with short assertion lifetimes,
TLS transport, and single-use or one-time-use checks on the response ID so
a duplicate submission is refused.

## Assertion Signing Risk Explanation

If assertions are not signed, the SP has no cryptographic proof that the
assertion came from the Keycloak IdP or that its contents are intact. An
attacker able to inject or modify traffic, or to supply their own
"assertion" to the ACS endpoint, could change the `NameID` to impersonate
any user and change the `MedDefenseRole` value to escalate from
`clinical_staff` to `it_security` or higher. Signing with the IdP's private
key closes this: the SP verifies the signature against the IdP's published
public key, so any modification of the subject, conditions or attribute
values invalidates the signature and the response is rejected. Both
`d.walsh` and `r.kim` assertions carry a signature covering the assertion,
and the realm export confirms `saml.assertion.signature` and
`saml.server.signature` are enabled. The remaining risk in this lab is that
the signature value is simulated; in production the SP must pin and verify
against the real IdP signing certificate and treat unsigned or invalidly
signed responses as failures.

## Off-Boarding and Centralized Identity Impact

Today MedDefense disables accounts system by system, and the incident showed
the consequence: two Epic accounts belonging to departed employees stayed
active because off-boarding checklists were not synchronized across Epic,
PACS, pharmacy and the clinical communication platform. Under SSO with a
centralized IdP, each downstream application trusts a single authentication
event from realm `meddefense`, so disabling the user's Keycloak account
blocks every connected service at once. There is one place to check for
enabled accounts, one place where MFA and brute force policy apply, and one
session idle timeout (30 minutes) bounding access after abandonment. This
directly removes the stale-account class of risk observed in the incident
response: an off-boarding action in the IdP becomes a complete off-boarding
action everywhere, and periodic review of a single user directory replaces
reconciling independent account databases.

---
