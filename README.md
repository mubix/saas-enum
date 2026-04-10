# SaaS Enum

Enumerate SaaS providers used by an organization through passive DNS TXT record analysis. SaaS vendors commonly require domain owners to add verification TXT records to prove ownership. `saas-enum` uses a rules engine to fingerprint these records, map them back to specific providers, and explain the security impact of each finding.

```
    ____             ____    ______
   / __/__ ____ ___ / __/__ / /_  /__ _  __
  _\ \/ _ `/ _ `(_-</ _// _ \/ / / / '_ \/ _ \
 /___/\_,_/\_,_/___/___/_//_/_/_\_\/_//_/\_,_/

   SaaS Enumeration via DNS TXT Records
```

## Installation

`saas-enum` is a standalone Ruby script with no external gem dependencies. It uses only the Ruby standard library (`resolv`, `yaml`, `json`, `optparse`).

### Requirements

- Ruby >= 2.7

### Setup

```bash
git clone https://github.com/mubix/saas-enum.git
cd saas-enum
chmod +x saas-enum
```

No `bundle install` required.

## Usage

### Quick start

```bash
# Single domain
./saas-enum -d example.com

# Multiple domains
./saas-enum -d example.com -d other.org

# Domain list from file
./saas-enum -f domains.txt

# JSON output (for piping to jq, SIEMs, or other tools)
./saas-enum -d example.com --json

# Show TXT records that didn't match any rule
./saas-enum -d example.com --show-unmatched
```

The domain list file is one domain per line. Blank lines and `#` comments are ignored:

```
# Fortune 500 targets
example.com
other.org
third.net
```

### Example output

```
  ══════════════════════════════════════════════════════════════════════════
  example.com  -- 3 providers found (5 records)
  ══════════════════════════════════════════════════════════════════════════

  ┌ Atlassian  [collaboration]
  │ Atlassian Cloud suite including Jira, Confluence, Trello, and Bitbucket
  │ IMPACT: Compromised credentials expose Confluence wikis (often containing
  │         architecture docs, runbooks, credentials), Jira tickets with
  │         vulnerability details, and Bitbucket source code repositories
  └ rec: atlassian-domain-verification=abc123...

  ┌ Okta  [identity]
  │ Enterprise identity and access management platform providing SSO, MFA,
  │ and lifecycle management
  │ IMPACT: Compromised admin credentials provide access to the organization's
  │         entire SSO fabric, with the ability to impersonate any user, modify
  │         MFA policies, create backdoor accounts, and pivot into every
  │         connected application
  └ rec: okta-domain-verification=xyz789...

  ┌ GlobalSign  [pki]
  │ Certificate authority providing SSL/TLS, code signing, and digital
  │ identity certificates
  │ IMPACT: Dangling SaaS: attacker could potentially complete domain
  │         validation and issue TLS/SSL certificates for the domain,
  │         enabling man-in-the-middle attacks or code signing fraud
  └ rec: globalsign-domain-verification=...

  ──────────────────────────────────────────────────────────────────────────
  3 provider(s) detected across 5 verification record(s)
```

Each detected provider includes:

- **Description**: what the service does and why organizations use it
- **Impact**: what an attacker could do with compromised credentials for that platform, or (for CAs and domain-claim-only services) what a Dangling SaaS takeover enables

When writing to a terminal, provider names and impact labels are color-coded. Colors are automatically stripped when output is piped to a file or another command.

### JSON output

```bash
./saas-enum -d example.com --json
```

Returns structured JSON suitable for piping into `jq`, feeding into other tools, or importing into a SIEM:

```json
[
  {
    "domain": "example.com",
    "providers": [
      {
        "name": "Atlassian",
        "category": "collaboration",
        "description": "Atlassian Cloud suite including Jira, Confluence, Trello, and Bitbucket",
        "impact": "Compromised credentials expose Confluence wikis...",
        "website": "https://www.atlassian.com",
        "record": "atlassian-domain-verification=abc123...",
        "reference": "https://support.atlassian.com/..."
      }
    ],
    "unmatched_records": [],
    "resolver_errors": []
  }
]
```

### HTML reports

```bash
./saas-enum -d example.com --html report.html
```

Generates a standalone HTML file with a dark-themed, responsive layout. Provider cards expand to show description, impact, and all matching records. No external dependencies; the report is a single self-contained file suitable for sharing with stakeholders or attaching to assessments.

### All options

```
Usage: saas-enum [options]

Options:
    -d, --domain DOMAIN      Target domain to enumerate
    -f, --file FILE          File containing list of domains (one per line)
        --json               Output results as JSON
        --html FILE          Generate HTML report to FILE
        --show-unmatched     Show TXT records that didn't match any rule
        --skip-cname         Skip CNAME/MX/NS detection (TXT records only)
        --zonewalk           Enable DNSSEC NSEC zone walking for subdomain discovery
        --timeout SECONDS    DNS query timeout per resolver (default: 10)
        --rules-dir DIR      Path to rules directory (default: ./rules)
    -v, --verbose            Show resolver errors and debug info
    -h, --help               Show this help message
        --version            Show version
```

## How It Works

`saas-enum` uses three detection techniques, each with its own rule file:

### Phase 1: TXT Record Matching

For each target domain, TXT records are queried across six DNS resolvers (system default, Google `8.8.8.8`/`8.8.4.4`, Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`, OpenDNS `208.67.222.222`). Results are merged and deduplicated. Ruby's `Resolv::DNS` is monkey-patched to force TCP for all queries, ensuring reliable retrieval of large TXT record sets that would otherwise be truncated or dropped over UDP.

Each TXT record is tested against rules in `rules/saas_providers.yml`. Rules support four match types:
- **`prefix`**: Record starts with the pattern (most common, e.g. `atlassian-domain-verification=`)
- **`substring`**: Pattern appears anywhere in the record
- **`regex`**: Full regular expression match
- **`spf_include`**: Matches `include:` directives inside SPF records (e.g. `_spf.salesforce.com`)

### Phase 2: CNAME, MX, and NS Detection

Rules in `rules/saas_cnames.yml` define known SaaS provider infrastructure domains. For each rule, the tool:

1. **Probes common subdomains** (e.g. `sso`, `login`, `support`, `help`, `careers`) and checks if they CNAME to a known provider domain
2. **Checks MX records** for email providers (e.g. `protection.outlook.com` for Microsoft 365, `pphosted.com` for Proofpoint)
3. **Checks NS delegations** for providers that host subzones (e.g. Shopify, WordPress)

This catches SaaS usage that doesn't leave TXT verification records. For example, `auth.company.com` pointing to `company.okta.com` reveals Okta usage even if there's no `okta-domain-verification=` TXT record.

Results are deduplicated against TXT findings so providers aren't reported twice.

### Phase 3: DNSSEC Zone Walking (optional)

With `--zonewalk`, the tool attempts NSEC-based zone walking to enumerate all names in the target's DNS zone. Discovered subdomains are then checked against CNAME rules. This only works when the zone has DNSSEC enabled with NSEC records (not NSEC3). Inspired by [saas-reconn](https://github.com/vanjo9800/saas-reconn)'s zone walking capabilities.

### Output

Matches from all phases are combined, deduplicated by provider name, and displayed as a card layout (default), JSON (`--json`), or HTML report (`--html`). ANSI colors are only emitted when writing to a terminal.

## Why This Matters

Organizations accumulate SaaS subscriptions rapidly. Each subscription typically leaves behind a DNS TXT record that was added during the initial domain verification step. These records persist long after the service is decommissioned, creating a map of every SaaS product the organization has ever verified, visible to anyone who can run `dig TXT`.

This matters from two angles:

**Credential compromise.** Each detected SaaS provider is a potential target for credential-based attacks. If an attacker obtains employee credentials through phishing, vishing, or data breaches, knowing which platforms the organization uses tells them exactly where to try those credentials. The per-provider impact statements in `saas-enum` output make this risk concrete:

- **Identity providers** (Okta, Azure AD, Duo): Compromised admin credentials can cascade to every connected application.
- **Code repositories** (GitHub, GitLab, Bitbucket): Source code, CI/CD secrets, deployment keys.
- **Security tools** (CrowdStrike, Wiz, SentinelOne): Attackers can study defenses, disable protections, or whitelist malware.
- **HR/Finance platforms** (SuccessFactors, Rippling, Stripe): Employee PII, payroll data, payment information.
- **Communication platforms** (Slack, Teams, Zoom): Searchable message history often contains credentials, architecture details, and business intelligence.

**Dangling SaaS.** Stale verification records can be exploited directly, without any credentials at all. See the full writeup below.

## Dangling SaaS

**Dangling SaaS** is a class of misconfiguration analogous to [dangling DNS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover), but instead of an orphaned CNAME pointing at an unclaimed resource, it is an orphaned **verification TXT record** that still asserts domain ownership for a SaaS provider the organization no longer uses.

### How It Works

Most SaaS platforms follow a common domain verification flow:

1. The organization signs up for a SaaS product (e.g., Acme Collaboration Suite).
2. The vendor says: *"Add this TXT record to prove you own `example.com`."*
3. IT adds `acme-domain-verification=abc123` to the domain's DNS.
4. The vendor checks the record, marks the domain as verified, and provisions the tenant.
5. Months or years later, the organization cancels the Acme subscription. The tenant is deprovisioned or abandoned.
6. **The TXT record stays.** No one remembers to remove it.

At this point, the domain is in a **Dangling SaaS** state for that provider. The verification record is still live, publicly visible, and (depending on the vendor) still considered valid proof of domain ownership.

### The Attack

An attacker who discovers a Dangling SaaS record can attempt the following:

1. **Identify the provider.** Tools like `saas-enum` make this trivial. The attacker sees `acme-domain-verification=abc123` in the target's TXT records and knows the target once used (or still uses) Acme.
2. **Register a new tenant.** The attacker signs up for their own Acme account and attempts to verify `example.com` as their domain.
3. **Exploit the lingering record.** If Acme's verification logic simply checks whether the expected TXT record exists (and the original record is still present, or the vendor reuses the same verification token), the attacker's tenant is now verified for the target's domain.
4. **Abuse the verified tenant.** Depending on the provider, this can enable:
   - **Receiving email** intended for the organization (if the SaaS handles mail routing).
   - **Impersonating the organization** on the platform, appearing as a legitimate tenant to partners, customers, or employees.
   - **Issuing certificates or tokens** in the organization's name (for providers that gate certificate issuance on domain verification, such as PKI/CA services).
   - **Accessing SSO/federation flows.** If the SaaS is an identity provider, the attacker may be able to insert themselves into authentication chains.
   - **Data exfiltration via trust.** Other integrated systems that trust the SaaS tenant (webhooks, API callbacks, OAuth grants) may route data to the attacker's instance.

### Real-World Considerations

The feasibility of a Dangling SaaS attack varies by provider:

- **Some vendors reuse verification tokens.** If the token is deterministic (e.g., derived from the domain name), any new tenant requesting verification of the same domain will look for the same TXT record and find it already present.
- **Some vendors generate a new token per tenant.** In this case, the original dangling record won't help the attacker directly, but it still signals that the organization once used the product and may have residual configuration (OAuth apps, API keys, webhook endpoints) that assumes the provider is trusted.
- **Some vendors don't fully deprovision.** The old tenant may still exist in a suspended state, and a social engineering or account recovery attack may reactivate it with the domain already verified.

### Remediation

1. **Audit your DNS TXT records regularly.** Run `saas-enum` against your own domains. Every verification record you find should correspond to an active, managed SaaS subscription.
2. **Remove stale verification records.** When you cancel a SaaS subscription, add "remove the DNS verification record" to your deprovisioning checklist. This is the single most effective mitigation.
3. **Maintain a SaaS inventory.** Know what you're paying for and what you've stopped paying for. Cross-reference this inventory with your DNS.
4. **Monitor for new tenants.** Some SaaS providers offer domain claim notifications. Enable them where available so you're alerted if someone attempts to verify your domain.
5. **Coordinate with your DNS team.** In large organizations, the team canceling the SaaS subscription is rarely the team managing DNS. Build a process that bridges this gap.
6. **Treat verification records like credentials.** A verification TXT record is a standing assertion that your organization trusts a particular provider. If that trust has been revoked, the assertion should be revoked too.

### Inventory Template

Use the following as a starting point for tracking your SaaS verification records:

| Domain | Provider | TXT Record | Status | Owner | Last Verified |
|--------|----------|------------|--------|-------|---------------|
| example.com | Atlassian | `atlassian-domain-verification=...` | Active | IT Ops | 2026-01-15 |
| example.com | DocuSign | `docusign=...` | **STALE, removed 2026-03** | Legal | 2025-06-01 |
| example.com | Miro | `miro-verification=...` | **DANGLING** | Unknown | Unknown |

## Rules

Rules are split across two YAML files in the `rules/` directory:

- **`saas_providers.yml`**: TXT record matching rules (194 rules across 29 categories)
- **`saas_cnames.yml`**: CNAME, MX, and NS detection rules (49 rules)

Both were sourced from scanning S&P 500 companies, Fortune Global 500, top universities worldwide, government agencies, healthcare organizations, NGOs, law firms, media companies, and tech startups.

### TXT rules

Each TXT rule is a YAML entry:

```yaml
- name: Atlassian
  category: collaboration
  description: Atlassian Cloud suite including Jira, Confluence, Trello, and Bitbucket
  website: https://www.atlassian.com
  match_type: prefix
  pattern: "atlassian-domain-verification="
  impact: >-
    Compromised credentials expose Confluence wikis (often containing architecture
    docs, runbooks, credentials), Jira tickets with vulnerability details, and
    Bitbucket source code repositories
  reference: https://support.atlassian.com/organization-administration/docs/verify-a-domain-for-your-organization/
```

### Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | SaaS provider display name |
| `category` | Yes | Provider category (see below) |
| `description` | Yes | What the service does and why organizations use it |
| `website` | Yes | Provider website URL |
| `match_type` | Yes | One of: `prefix`, `substring`, `regex`, `spf_include` |
| `pattern` | Yes | The string or regex to match |
| `impact` | Yes | What an attacker could do with compromised credentials, or Dangling SaaS risk |
| `reference` | No | URL documenting the provider's verification process |

### Impact field guidelines

The `impact` field should describe the security risk from one of two angles:

1. **Credential compromise** (primary): What can an attacker do if they obtain valid credentials for this platform through phishing, vishing, or data breaches? Focus on the most sensitive data or capabilities accessible. Start with "Compromised credentials..."

2. **Dangling SaaS** (secondary): For providers where credential access doesn't apply (certificate authorities, browser publisher verification, notification-only services), describe the domain takeover risk. Start with "Dangling SaaS:..."

### CNAME rules

CNAME rules detect SaaS providers by checking whether an organization's subdomains resolve to known provider infrastructure. Each rule can include multiple detection vectors:

```yaml
- name: Okta
  category: identity
  description: Enterprise identity and access management platform
  website: https://www.okta.com
  impact: >-
    Compromised admin credentials provide access to the organization's entire
    SSO fabric, with the ability to impersonate any user and pivot into every
    connected application
  cname_targets:
    - "okta.com"
    - "oktapreview.com"
    - "okta-dnssec.com"
  subdomains_to_check:
    - sso
    - login
    - auth
    - id
```

| Field | Required | Description |
|-------|----------|-------------|
| `cname_targets` | Yes | Domain suffixes indicating this provider. If a subdomain's CNAME points to a domain ending in one of these, the provider is detected |
| `subdomains_to_check` | No | Common subdomain names to probe (e.g. `sso`, `support`, `help`). The tool resolves `{name}.{target}` for each |
| `mx_targets` | No | Domain suffixes in MX records. Checked against the target's mail exchange records |
| `ns_targets` | No | Domain suffixes in NS records. For providers that host delegated subzones |
| `ip_ranges` | No | CIDR ranges for IP-based detection (use sparingly; IPs change) |

### Categories

`analytics`, `asset_management`, `automation`, `cloud`, `cms`, `collaboration`, `communication`, `compliance`, `crm`, `data`, `design`, `devtools`, `email`, `hr`, `identity`, `iot`, `it_management`, `marketing`, `monitoring`, `networking`, `payments`, `pki`, `project_management`, `security`, `social`, `storage`, `support`, `transportation`, `video`

## Contributing

Contributions of new rules are the most impactful way to improve `saas-enum`. If you've encountered a SaaS provider that requires DNS TXT verification and it's not already covered, please submit a PR.

### Adding a new rule

1. **Find the verification record.** Run `dig TXT yourdomain.com` on a domain you know uses the provider, or check the provider's documentation for their domain verification instructions.

2. **Identify the pattern.** Most verification records follow predictable formats:
   - `providername-domain-verification=TOKEN`
   - `providername-site-verification=TOKEN`
   - `providername-verify=TOKEN`
   - `providername=TOKEN`

3. **Add the rule to `rules/saas_providers.yml`:**

   ```yaml
   - name: Acme Platform
     category: collaboration
     description: Project management suite for cross-functional teams with Gantt charts and resource planning
     website: https://www.acme.com
     match_type: prefix
     pattern: "acme-domain-verification="
     impact: >-
       Compromised credentials expose project timelines, resource assignments,
       budget allocations, and file attachments across the organization's
       project portfolio
     reference: https://docs.acme.com/domain-verification
   ```

4. **Test your rule:**

   ```bash
   ./saas-enum -d yourdomain.com --show-unmatched
   ```

   Verify that your new provider appears in the matched results and no longer shows in unmatched.

5. **Submit a pull request** with:
   - The rule addition in `rules/saas_providers.yml`
   - A brief note on where you found the verification pattern (provider docs, observed in the wild, etc.)

### Guidelines

- **Prefer `prefix` match type** unless the pattern genuinely requires `substring` or `regex`. Prefix matching is the most predictable for contributors to reason about.
- **Don't include secrets or tokens** in your examples or test data. The *pattern* is the prefix/structure, not the token value.
- **One rule per verification method.** If a provider uses multiple distinct verification record formats, add a separate rule for each.
- **Include a `reference` URL** when possible. A link to the provider's documentation on domain verification helps future maintainers verify the rule is correct.
- **Write specific impact statements.** "Exposes sensitive data" is not helpful. Name the data: "Compromised credentials expose Confluence wikis containing architecture docs, runbooks, and stored credentials."

### Discovering new providers

The `--show-unmatched` flag is your friend. Run `saas-enum` against large enterprise domains and look at the unmatched TXT records. Anything that looks like a verification record (has a `=`, contains `verification` or `verify`, has a UUID-style value) is a candidate for a new rule.

## Prior Work and References

This project builds on ideas from several existing tools and resources:

- **[saas-reconn](https://github.com/vanjo9800/saas-reconn)**: A Go-based reconnaissance tool for SaaS platform discovery by [@vanjo9800](https://github.com/vanjo9800). `saas-reconn`'s multi-technique approach (certificate transparency, DNSSEC zone walking, CNAME subdomain pattern matching, and provider behavioral analysis) directly inspired our CNAME/MX detection engine and DNSSEC zone walking feature. While `saas-reconn` focuses on subdomain enumeration and active HTTP validation, `saas-enum` takes a complementary approach centered on DNS TXT verification records with a contributor-friendly YAML rules engine.
- **[Enumeration-as-a-Service](https://github.com/sosdave/Enumeration-as-a-Service)**: An early script by [@sosdave](https://github.com/sosdave) that enumerates SaaS offerings via DNS queries. `saas-enum` expands on this concept with a pluggable rules engine, multi-resolver lookups, and the Dangling SaaS framework.
- **[cloud_enum](https://github.com/initstring/cloud_enum)**: Multi-cloud OSINT tool for enumerating public resources in AWS, Azure, and GCP.
- **[Detecting Dangling SaaS Subdomains and Real Subdomain Takeovers](https://www.secureideas.com/blog/detecting-dangling-saas-subdomains-and-real-subdomain-takeovers)**: A blog post by Secure Ideas exploring the concept of dangling SaaS subdomains and their relationship to subdomain takeover attacks. This was an early articulation of the risk that `saas-enum` generalizes into the broader "Dangling SaaS" framework, extending it to include TXT verification records alongside CNAME-based takeovers.
- **[OWASP Testing Guide: Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)**: The dangling DNS concept that Dangling SaaS extends.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
