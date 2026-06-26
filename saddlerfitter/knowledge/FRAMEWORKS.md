# Frameworks saddlerFitter grounds its recommendations in

saddlerFitter does not invent its own notion of "good code". Every rule in
[`rules.yaml`](./rules.yaml) is traced to an established, citable standard, so a
finding reads as *"this violates X"* rather than *"the model didn't like this"*. The
catalog leans on UK guidance first (it is built for UK monorepo audits) and the
international standards that guidance itself references.

---

## 1. NCSC Secure Development & Deployment — 8 principles

The UK National Cyber Security Centre's developer guidance. High-level, durable, and
the backbone of how the catalog frames *process* recommendations.

| slug | principle |
|---|---|
| `secure-development-is-everyones-concern` | 1. Secure development is everyone's concern |
| `keep-security-knowledge-sharp` | 2. Keep your security knowledge sharp |
| `produce-clean-maintainable-code` | 3. Produce clean & maintainable code |
| `secure-your-development-environment` | 4. Secure your development environment |
| `protect-your-code-repository` | 5. Protect your code repository |
| `secure-the-build-and-deployment-pipeline` | 6. Secure the build and deployment pipeline |
| `continually-test-your-security` | 7. Continually test your security |
| `plan-for-security-flaws` | 8. Plan for security flaws |

Source: <https://www.ncsc.gov.uk/collection/developers-collection/principles>

saddlerFitter *is* an instance of principles 3, 7 and 8 — it produces maintainable-code
findings, it tests security continually (the gate + CVE watch), and it plans for
flaws (escalate-on-split, human approval).

---

## 2. Software Security Code of Practice (DSIT + NCSC, 2025) — 14 principles, 4 themes

The UK government's voluntary baseline for software vendors, launched at CyberUK
2025. Where the catalog's `code_of_practice` slugs (`CoP 1.4`, etc.) point.

**Theme 1 — Secure design and development**
- 1.1 Follow an established secure development framework.
- 1.2 Understand the composition of the software and assess third-party component risk across the lifecycle.
- 1.3 Have a clear process for testing software and updates before distribution.
- 1.4 Follow secure by design and secure by default principles.

**Theme 2 — Build environment security**
- 2.1 Protect the build environment against unauthorised access.
- 2.2 Control and log changes to the build environment.

**Theme 3 — Secure deployment and maintenance**
- 3.1 Distribute software securely to customers.
- 3.2 Implement and publish an effective vulnerability disclosure process.
- 3.3 Proactively detect, prioritise and manage vulnerabilities in software components.
- 3.4 Report vulnerabilities to relevant parties where appropriate.
- 3.5 Provide timely security updates, patches and notifications.

**Theme 4 — Communication with customers**
- 4.1 Specify the level of support and maintenance provided.
- 4.2 Give at least one year's notice before end of support.
- 4.3 Make information available about notable incidents.

Sources: <https://www.gov.uk/government/publications/software-security-code-of-practice> ·
<https://www.ncsc.gov.uk/collection/software-security-code-of-practice-implementation-guidance/about>

The CVE watch is the operational arm of **1.2** and **3.3**; the double-grill gate is
**1.3** and **1.4** enforced at push time.

---

## 3. OWASP — Top 10 (2021) and ASVS 5.0

International, widely adopted by UK organisations, and the level at which the
security lens reasons about *vulnerability classes*.

- **OWASP Top 10 (2021)** — A01 Broken Access Control · A02 Cryptographic Failures ·
  A03 Injection · A04 Insecure Design · A05 Security Misconfiguration · A06
  Vulnerable and Outdated Components · A07 Identification and Authentication Failures
  · A08 Software and Data Integrity Failures · A09 Security Logging and Monitoring
  Failures · A10 Server-Side Request Forgery.
- **OWASP ASVS 5.0** (May 2025, ~350 requirements across 17 chapters) — the
  verification standard. The catalog cites chapters where the mapping is direct, e.g.
  *V1 Encoding & Sanitization*, *V2 Validation & Business Logic*, *V5 File Handling*,
  *V8 Authorization*, *V11 Cryptography*, *V16 Security Logging & Error Handling*.

Sources: <https://owasp.org/www-project-top-ten/> ·
<https://owasp.org/www-project-application-security-verification-standard/>

---

## 4. MITRE CWE — the weakness taxonomy

Every rule carries one or more **CWE** identifiers. CWE is the stable join key
between saddlerFitter's findings, the OWASP categories, and external scanners (Bandit test
ids map cleanly to CWEs), so a finding can be cross-referenced regardless of which
detector raised it. Source: <https://cwe.mitre.org/>

---

## 5. Secure by Design (UK Government)

The cross-government approach (10 mandatory principles for central-government
delivery) that the Code of Practice's principle 1.4 echoes. saddlerFitter's *escalate, never
silently drop* and *deny-by-default authorization* recommendations are downstream of
it. Source: <https://www.security.gov.uk/policy-and-guidance/secure-by-design/>

---

## Rule → framework crosswalk

Generated from `rules.yaml` (31 rules). `DETECT` shows how each is identified —
`ast` (deterministic stdlib analyzer), `lens` (an LLM proposer lens), `external`
(opt-in Bandit/Ruff), `feed` (OSV/NVD/SBOM).

| RULE                    | LENS            | SEV    | CWE                | OWASP TOP 10                                        | CoP     | DETECT            |
|-------------------------|-----------------|--------|--------------------|-----------------------------------------------------|---------|-------------------|
| SEC-CMD-INJECTION       | security        | high   | CWE-78             | A03:2021 Injection                                  | CoP 1.4 | ast/external/lens |
| SEC-CODE-INJECTION      | security        | high   | CWE-94, CWE-95     | A03:2021 Injection                                  | CoP 1.4 | ast/external/lens |
| SEC-SQL-INJECTION       | security        | high   | CWE-89             | A03:2021 Injection                                  | CoP 1.4 | external/lens     |
| SEC-PATH-TRAVERSAL      | security        | high   | CWE-22             | A01:2021 Broken Access Control                      | CoP 1.4 | lens              |
| SEC-DESERIALIZATION     | security        | high   | CWE-502            | A08:2021 Software and Data Integrity Failures       | CoP 1.4 | external/lens     |
| SEC-HARDCODED-SECRET    | security        | high   | CWE-798            | A07:2021 Identification and Authentication Failures | CoP 2.1 | external/lens     |
| SEC-MISSING-AUTHZ       | security        | high   | CWE-862, CWE-285   | A01:2021 Broken Access Control                      | CoP 1.4 | lens              |
| SEC-SSRF                | security        | high   | CWE-918            | A10:2021 Server-Side Request Forgery                | CoP 1.4 | lens              |
| SEC-WEAK-CRYPTO         | security        | medium | CWE-327, CWE-328   | A02:2021 Cryptographic Failures                     | CoP 1.4 | external/lens     |
| SEC-INSECURE-RANDOM     | security        | medium | CWE-330            | A02:2021 Cryptographic Failures                     | CoP 1.4 | external/lens     |
| SEC-INPUT-VALIDATION    | security        | medium | CWE-20             | A03:2021 Injection                                  | CoP 1.4 | lens              |
| COR-NULL-DEREF          | correctness     | medium | CWE-476            | —                                                   | CoP 1.3 | lens              |
| COR-DIV-ZERO            | correctness     | medium | CWE-369            | —                                                   | CoP 1.3 | lens              |
| COR-OFF-BY-ONE          | correctness     | medium | CWE-193            | —                                                   | CoP 1.3 | lens              |
| COR-RACE-TOCTOU         | correctness     | high   | CWE-362, CWE-367   | —                                                   | CoP 1.4 | lens              |
| COR-RESOURCE-LEAK       | correctness     | medium | CWE-404, CWE-772   | —                                                   | CoP 1.3 | lens              |
| COR-UNCHECKED-RETURN    | correctness     | low    | CWE-252            | —                                                   | CoP 1.3 | lens              |
| COR-MUTABLE-DEFAULT     | correctness     | medium | CWE-665            | —                                                   | CoP 1.3 | ast/lens          |
| ERR-BARE-EXCEPT         | maintainability | medium | CWE-396, CWE-755   | —                                                   | CoP 1.3 | ast/lens          |
| ERR-SWALLOWED           | maintainability | medium | CWE-390, CWE-1069  | A09:2021 Security Logging and Monitoring Failures   | CoP 1.3 | ast/lens          |
| ERR-MISSING-LOGGING     | maintainability | low    | CWE-778            | A09:2021 Security Logging and Monitoring Failures   | CoP 3.3 | lens              |
| PERF-QUADRATIC          | performance     | low    | CWE-407            | —                                                   | CoP 1.3 | lens              |
| PERF-UNBOUNDED-RESOURCE | performance     | medium | CWE-400, CWE-770   | —                                                   | CoP 1.4 | lens              |
| PERF-REDOS              | performance     | medium | CWE-1333           | —                                                   | CoP 1.4 | lens              |
| PERF-BLOCKING-IO        | performance     | low    | CWE-1049           | —                                                   | CoP 1.3 | lens              |
| MNT-DUPLICATION         | maintainability | low    | CWE-1041           | —                                                   | CoP 1.1 | lens              |
| MNT-DEAD-CODE           | maintainability | info   | CWE-561            | —                                                   | CoP 1.1 | lens              |
| MNT-IDENTITY-COMPARE    | maintainability | info   | CWE-480            | —                                                   | CoP 1.1 | ast/lens          |
| MNT-UNCLEAR-NAMING      | maintainability | info   | CWE-1078           | —                                                   | CoP 1.1 | lens              |
| SUP-VULN-DEPENDENCY     | security        | high   | CWE-1395, CWE-937  | A06:2021 Vulnerable and Outdated Components         | CoP 3.3 | feed              |
| SUP-FLOATING-PIN        | security        | medium | CWE-1357, CWE-1104 | A08:2021 Software and Data Integrity Failures       | CoP 1.2 | feed/lens         |

Regenerate after editing the catalog: `python3 -m saddlerfitter.cli knowledge build`.
