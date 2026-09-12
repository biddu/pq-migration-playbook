# Post-quantum cryptography questionnaire for suppliers

*Template from* Post-Quantum Migration: An Engineer's Playbook, *Chapter 4. Send with the product name, version and the date by which you need answers. Ask for answers in writing from someone with a technical title. Every "roadmap" answer is a "no" with a date attached; record the date.*

| # | Question | What a good answer looks like | What a bad answer looks like |
|---|---|---|---|
| 1 | Which post-quantum algorithms does the current shipping version implement, by FIPS number and parameter set? | "ML-KEM-768 (FIPS 203) for TLS key exchange as the X25519MLKEM768 hybrid group; ML-DSA-65 (FIPS 204) for certificate verification; version 7.2, GA March 2026." | "We support Kyber." / "Quantum-safe encryption is on our roadmap." |
| 2 | For each of the following functions, is post-quantum support present today, planned with a date, or not planned: TLS key exchange; TLS server authentication (certificates); SSH; IPsec/IKEv2; code and firmware signing; data-at-rest key wrapping; API tokens (JWT/JOSE)? | A table with one of the three states per row and a version or quarter for each "planned". | A single yes. |
| 3 | Is the post-quantum key exchange hybrid (classical plus ML-KEM) or pure? Can the classical component be disabled by configuration, and can the post-quantum component be disabled by configuration? | "Hybrid by default; both components are independently configurable; pure ML-KEM available behind a flag." | "Hybrid, not configurable." / "We do not use hybrids." with no reason. |
| 4 | Which cryptographic library or module implements the algorithms, at which version, and is that module FIPS 140-3 validated with the post-quantum algorithms inside its boundary? Give the CMVP certificate number. | "OpenSSL 3.5.x via the FIPS provider; CMVP #NNNN covers ML-KEM and ML-DSA." or "Not yet validated; validation submitted on DATE." | "FIPS compliant." with no certificate number. |
| 5 | Does the product accept, and can it be configured to require, ML-DSA certificates in its trust store? Which parameter sets? What is the maximum certificate chain size it will accept? | "Accepts ML-DSA-44/65/87; requires can be configured per trust anchor; chain limit 64 KB." | "Certificates are handled by the platform." |
| 6 | For products that sign (updates, firmware, tokens): which signature algorithm is used, where is the key held, and what is the plan and date for moving to ML-DSA, SLH-DSA or a stateful hash-based scheme? Can our devices verify the new signatures today? | Algorithm, HSM or key store named, a dated plan, and a statement about verifier readiness. | "Our updates are signed." |
| 7 | What are the measured size and latency impacts of the post-quantum modes in your own testing (handshake bytes, records, CPU)? | Numbers with a test description. | "Negligible." |
| 8 | Which of the product's cryptographic settings are exposed to us for configuration, and which are fixed? Is there a machine-readable export of the effective cryptographic configuration or a CBOM? | "Full policy file; CycloneDX CBOM export in version 7.3." | "Configuration is managed by us for your security." |
| 9 | What is the product's end-of-support date, and will post-quantum support be delivered to the version we run or only to a later major version we must buy? | Dates and versions. | "Contact your account manager." |
| 10 | Which regulatory timelines does your post-quantum plan target (CNSA 2.0 January 2027 acquisition gate, NIST IR 8547 2030 deprecation, EU 2030 for high-risk systems), and what have you committed to customers in writing? | Named instruments and dates. | "We are monitoring the regulatory landscape." |
| 11 | Have you had an independent assessment of your post-quantum implementation (interoperability testing, side-channel review, CAVP algorithm testing)? By whom and when? | Named assessor, date, scope. | "Our engineers are experts." |
| 12 | Who is the named technical contact for cryptographic questions, and what is your process for notifying customers of cryptographic vulnerabilities and algorithm deprecations? | A person or team and a documented process. | "Support portal." |

## How to read the answers

Score each answer 2 (specific and dated), 1 (partial), 0 (absent or evasive). A total below 12 means the product cannot be on your critical path; plan to replace or isolate it. Any 0 on questions 1, 4 or 9 is a finding on its own. Record every date given; it becomes a node in the migration backlog (Lab 4.1) with the vendor as owner.

Five answers that mean "no": "roadmap" without a date; "Kyber" without "ML-KEM"; "FIPS compliant" without a certificate number; "negligible" without a measurement; "handled by the platform" for anything you need to configure.
