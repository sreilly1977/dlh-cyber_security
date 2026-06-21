# Task 0 - E-commerce Platform

Threat modeling of an e-commerce platform where users can:
- Browse products (no authentication required)
- Add items to cart (no authentication required)
- Checkout and pay (authentication required)
- View order history (authentication required)

The system architecture includes:
- React frontend
- Node.js API backend
- PostgreSQL database
- Stripe payment integration

## Questions

### 1. Identify three STRIDE threats for the checkout process. For each threat, specify:
- STRIDE category
- Threat description
- Potential impact
- Suggested mitigation

### 2. What trust boundaries exist in this system? Describe at least three.

### 3. Rate the threat of SQL injection in the product search functionality using DREAD (provide scores for each factor and justify them).

---

## 1. Three STRIDE Threats for the Checkout Process

### Threat 1: Tampering — Price Manipulation via Frontend Request
- **STRIDE Category:** Tampering
- **Description:** The React frontend sends cart items and prices to the Node.js API during checkout. An attacker intercepts the request (e.g., using browser dev tools or a proxy like Burp Suite) and modifies the price or total field before it reaches the server — say, changing a $999 item to $0.01 before submitting payment.
- **Potential Impact:** The attacker receives goods at a fraction of the cost. Revenue loss scales with attack automation. If widely exploited, this could be catastrophic — and if the server trusts the client-side price, there's no integrity check to catch it.
- **Suggested Mitigation:** We never trust client-side price data. The server should resolve prices from the database using only product IDs from the request. Additionally, we can implement server-side idempotency keys for payment processing and log all price discrepancies between expected and submitted amounts as potential fraud signals.

### Threat 2: Information Disclosure — Payment Data Interception
- **STRIDE Category:** Information Disclosure
- **Description:** If the checkout page doesn't enforce TLS properly (e.g., mixed content, expired certificates, or accepting HTTP requests), an attacker on the network path (for example on public Wi-Fi) could intercept payment card details, session tokens, or personally identifiable information in transit.
- **Potential Impact:** Exposed payment data leads directly to credit card fraud, PCI-DSS violations, and regulatory penalties. Session token leakage enables account takeover. A single intercepted checkout can compromise a user's financial identity.
- **Suggested Mitigation:** We can enforce HTTPS site-wide with HSTS headers (including includeSubDomains and a long max-age). We can use Stripe's hosted payment fields or Stripe Elements, which keep card data in Stripe's iframes — never touching our server. We can validate TLS configurations with tools like SSL Labs, and implement CSP headers to prevent mixed-content loading.

### Threat 3: Spoofing — Session Hijacking at Checkout
- **STRIDE Category:** Spoofing
- **Description:** An attacker steals an authenticated user's session token (via XSS, insecure cookie flags, or network sniffing) and initiates a checkout pretending to be that victim. They ship goods to their own address or drain stored payment methods.
- **Potential Impact:** Financial loss for the victim, fraudulent charges, and chargeback costs for the platform. Repeated incidents erode customer trust and can result in increased Stripe processing fees or account suspension.
- **Suggested Mitigation:** We can set cookies with Secure, HttpOnly, and SameSite=Strict flags. We can implement re-authentication (require password re-entry or MFA) before completing payment, especially for stored payment methods. We can bind sessions to IP and user-agent and flag anomalies. We can implement short-lived checkout sessions with token expiration.

## 2. Trust Boundaries

A trust boundary exists wherever data or control flows cross from a zone of one trust level to another. Here are the critical ones:

**Boundary 1: User Browser → React Frontend → Node.js API**
This is the most exposed boundary. The browser is entirely untrusted — all data arriving from it (form inputs, cart contents, auth tokens, headers) could be tampered with. The API must validate and sanitize everything crossing this line. Key risks: parameter tampering, injection attacks, forged authentication tokens, replayed requests.

**Boundary 2: Node.js API → PostgreSQL Database**
Data flowing from the application layer to the database crosses from a partially trusted zone (our code, which could still have bugs) to a highly trusted data store. The risk here is that a vulnerability in the API (like SQL injection or improper input validation) allows untrusted data to reach the database and execute as trusted commands. Parameterized queries and least-privilege database credentials are essential controls at this boundary.

**Boundary 3: Node.js API → Stripe Payment Gateway**
Here, our server communicates with an external system outside our control. This boundary runs both ways: we send payment intents, and Stripe sends webhook confirmations back. Risks include: a malicious actor spoofing Stripe webhook callbacks (confirming payments that never happened), man-in-the-middle attacks on the outbound request, or credential leakage of our Stripe API keys. Mitigations include webhook signature verification, mutual TLS where applicable, and storing API keys in a secrets manager — never in code or environment variables accessible to the frontend.

## 3. DREAD Rating: SQL Injection in Product Search

The product search is unauthenticated, meaning anyone on the internet can hit it. That's significant.

| Factor | Score (0-10) | Justification |
| :--- | :---: | :--- |
| **Damage** | 8 | SQL injection on the search endpoint likely hits a read-heavy path. An attacker could extract the entire database — customer PII, payment records (even partial), order history, credentials. Worst case with stacked queries or privileged DB users: data modification or dropping tables. |
| **Reproducibility** | 9 | Product search is a public, predictable endpoint. An attacker can iterate on payloads at will with no rate limiting or authentication friction. Once a working payload is found, it works every time. |
| **Exploitability** | 7 | Automated tools (sqlmap) make exploitation straightforward if the vulnerability exists. However, whether stacked queries or UNION-based extraction works depends on the specific ORM/query construction and DB permissions — so there's some variability. |
| **Affected Users** | 10 | A successful SQL injection affecting the shared PostgreSQL database compromises all users — every customer record, every order, every piece of data in that database. This isn't limited to the attacker's session. |
| **Discoverability** | 9 | The search endpoint is trivially discoverable — it's on the public-facing storefront. No authentication barrier. Automated scanners and reconnaissance tools will find it immediately. |

**Total DREAD Score: 43/50**

This is a critical rating. The combination of an unauthenticated entry point with access to a shared database makes this a top-priority finding. In real-world terms, this is the kind of vulnerability that leads to breach disclosure headlines.

**Key mitigations:** We should use parameterized queries exclusively (never string concatenation for SQL). If using an ORM, we need to avoid raw query methods. We need to apply the principle of least privilege to the database user connecting from the API — it should not be able to access tables unrelated to product search. Implementing input validation and rate limiting on the search endpoint is a must. We should consider a WAF as an additional layer, but never as a primary defense against injection.
