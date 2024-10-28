---
title: "Use of Composite ML-DSA in TLS 1.3"
abbrev: "Use of Composite ML-DSA in TLS 1.3"
category: std

docname: draft-tls-reddy-composite-mldsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "TLS"
keyword:
 - ML-DSA
 - FIPS204
 - Composite

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Timothy Hollebeek
    organization: DigiCert
    city: Pittsburgh
    country: USA
    email: "tim.hollebeek@digicert.com"
 -
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com

normative:
 RFC8446:
 TLSIANA: I-D.ietf-tls-rfc8447bis
 I-D.ietf-lamps-pq-composite-sigs:
informative:
 I-D.ietf-pquip-pqt-hybrid-terminology:
 FIPS204:
   title: "FIPS-204: Module-Lattice-Based Digital Signature Standard"
   target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
   date: false
 BSI2021:
   title: "Quantum-safe cryptography - fundamentals, current developments and recommendations"
   target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Brochure/quantum-safe-cryptography.pdf
   author:
     - org: "Federal Office for Information Security (BSI)"
   date: October 2021
 
--- abstract

This document specifies how the post-quantum signature scheme ML-DSA {{FIPS204}}, in combination with traditional algorithms RSA-PSS, ECDSA, and Ed25519, can be used for authentication in TLS 1.3. The composite ML-DSA approach is beneficial in deployments where operators seek additional protection against potential breaks or catastrophic bugs in ML-DSA.

--- middle

# Introduction

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA, Diffie-Hellman, DSA, and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies {{BSI2021}}.

ML-DSA {{FIPS204}} is a post-quantum signature schemes standardised by NIST. It is a module-lattice based scheme.

This memo specifies how a composite ML-DSA can be negotiated for authentication in TLS 1.3 via the "signature_algorithms" and "signature_algorithms_cert" extensions.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This document is consistent with the terminology defined in {{I-D.ietf-pquip-pqt-hybrid-terminology}}. It defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

# ML-DSA SignatureSchemes Types
As defined in {{RFC8446}}, the SignatureScheme namespace is used for
the negotiation of signature scheme for authentication via the
"signature_algorithms" and "signature_algorithms_cert" extensions.
This document adds new SignatureSchemes types for the composite ML-DSA as follows.

~~~
enum {
  mldsa44_ecdsa_secp256r1_sha256 (0x0907),
  mldsa65_ecdsa_secp384r1_sha384 (0x0908),
  mldsa87_ecdsa_secp384r1_sha384 (0x0909),
  mldsa44_ed25519 (0x090A),
  mldsa65_ed25519 (0x090B),
  mldsa44_rsa_pss_rsae_sha256 (0x090C),
  mldsa65_rsa_pss_rsae_sha384 (0x090D),
  mldsa87_rsa_pss_rsae_sha512 (0x090E),
  mldsa44_rsa_pss_pss_sha256 (0x090F),
  mldsa65_rsa_pss_pss_sha384 (0x0910),
  mldsa87_rsa_pss_pss_sha512 (0x0911)
} SignatureScheme;
~~~

Each entry specifies a unique combination of an ML-DSA parameter, an elliptic curve or RSA variant, and a hashing function. The first algorithm corresponds to ML-DSA-44, ML-DSA-65, and ML-DSA-87, as defined in {{FIPS204}}. It is important to note that the mldsa* entries represent the pure versions of these algorithms and should not be confused with prehashed variants, such as HashML-DSA-44, also defined in {{FIPS204}}.

In TLS, the data used for generating a digital signature is unique for each TLS session, as it includes the entire handshake. Thus, ML-DSA can utilize the deterministic version. The context parameter defined in {{FIPS204}} Algorithm 2/Algorithm 3 MUST be an empty string.

The corresponding end-entity certificate when negotiated MUST
use the First AlgorithmID and Second AlgorithmID respectively as
defined in {{I-D.ietf-lamps-pq-composite-sigs}}.

# Security Considerations

The security considerations discussed in Section 11 of {{I-D.ietf-lamps-pq-composite-sigs}} needs
to be taken into account. 


# IANA Considerations

This document requests new entries to the TLS SignatureScheme registry,
according to the procedures in {{Section 6 of TLSIANA}}.

| Value   | Description                         | Recommended | Reference      |
|---------|-------------------------------------|-------------|----------------|
| 0x0907  | mldsa44_ecdsa_secp256r1_sha256      | Y           | This document. |
| 0x0908  | mldsa65_ecdsa_secp384r1_sha384      | Y           | This document. |
| 0x0909  | mldsa87_ecdsa_secp384r1_sha384      | Y           | This document. |
| 0x090A  | mldsa44_ed25519                     | Y           | This document. |
| 0x090B  | mldsa65_ed25519                     | Y           | This document. |
| 0x090C  | mldsa44_rsa_pss_rsae_sha256         | Y           | This document. |
| 0x090D  | mldsa65_rsa_pss_rsae_sha384         | Y           | This document. |
| 0x090E  | mldsa87_rsa_pss_rsae_sha512         | Y           | This document. |
| 0x090F  | mldsa44_rsa_pss_pss_sha256          | Y           | This document. |
| 0x0910  | mldsa65_rsa_pss_pss_sha384          | Y           | This document. |
| 0x0911  | mldsa87_rsa_pss_pss_sha512          | Y           | This document. |

--- back

# Acknowledgments
{:numbered="false"}

TODO