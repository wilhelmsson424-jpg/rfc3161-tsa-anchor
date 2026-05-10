# rfc3161-tsa-anchor

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node 20+](https://img.shields.io/badge/Node-20%2B-339933.svg)](https://nodejs.org/)

Dual-anchor RFC 3161 Time Stamping Authority client for Node.js.

Anchors a SHA-256 hash against two independent TSA providers in sequence so that the timestamp survives a 7+ year retention horizon even if one provider goes dark, gets compromised, or stops responding to requests from your network range.

## Why dual

A single TSA is a single point of failure on a long retention horizon. The cost of being wrong is "we cannot legally prove when this record existed". Dual-anchor is cheap insurance. The default providers are:

- **Primary:** `freetsa.org` (free, EU-based, accepted by Skatteverket and most Swedish auditors)
- **Backup:** `tsa.swisssign.net` (commercial, Switzerland)

Operational note: `timestamp.digicert.com` is reachable from many networks but may be blocked from some cloud regions due to outbound firewall policy. If you observe `EHOSTUNREACH` against DigiCert from a hosted environment, configure SwissSign or `zeitstempel.dfn.de` (TU Berlin) instead.

## What you get

- `buildTSQ(hash)` to produce a DER-encoded TimeStampReq
- `postTSQ(url, tsq)` to POST it and receive the TimeStampResp
- `parseTSR(tsr)` to extract status, token bytes, and `genTime`
- `verifyTSRMessageImprint(tsr, expectedHash)` so a malicious TSA cannot timestamp a different hash than you submitted (RFC 3161 § 2.4.2)
- `verifyTSRSignature(tsr, caCertPem)` for CMS signature verification against a trusted root cert
- `anchorHash(hashHex, opts)` for single-provider anchoring with retry and exponential backoff
- `anchorHashDual(hashHex, opts)` for sequential dual-anchoring with explicit `partial` flag when only one provider succeeds

## Quickstart

```bash
git clone https://github.com/wilhelmsson424-jpg/rfc3161-tsa-anchor
cd rfc3161-tsa-anchor
npm install
npm test
```

```js
import { anchorHashDual } from 'rfc3161-tsa-anchor';

const hashHex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const result = await anchorHashDual(hashHex);

console.log({
  succeeded: result.anchors.length,
  failed: result.failures.length,
  partial: result.partial,
  primaryGenTime: result.anchors[0]?.genTime,
});
```

## Verifying the timestamp later

The returned `token` is a DER-encoded `TimeStampToken` that any RFC 3161-aware verifier can re-check. Common command-line tools:

```bash
# OpenSSL: verify the response and extract the timestamp
openssl ts -reply -in token.tsr -text

# Verify against the original hash and the provider's CA chain
openssl ts -verify -data your-document.dat \
  -in token.tsr \
  -CAfile freetsa-cacert.pem
```

## Defensive choices

- **Constant-time comparison** for `messageImprint` checks to defend against timing attacks
- **Depth-limited recursive walk** when extracting `messageImprint` so a pathological TSR cannot cause stack overflow or quadratic blowup
- **Sequential** rather than parallel dual-anchor because some commercial TSAs rate-limit or fail TLS handshake under parallel load from a single source IP
- **Explicit `partial` flag** with a console warning when only one provider succeeded, so silent single-anchor mode cannot creep in unnoticed

## Licensing of TSA services

This library connects to third-party TSA services. Verify the licensing of the providers you choose for your jurisdiction and use case. `freetsa.org` is free for non-commercial use; commercial TSAs typically have per-token pricing or subscription terms. The default settings are sensible defaults, not legal advice.

## Disclaimer

This is a technical reference implementation. Whether a TSR is admissible as evidence in a legal proceeding depends on the jurisdiction, the verifier, and operational details (chain-of-custody, archive integrity). Consult a qualified Swedish auditor or lawyer for your specific situation.

## License

MIT. See [LICENSE](LICENSE).

## Author

Built by [Wilhelmsson Labs](https://github.com/wilhelmsson424-jpg). Pull requests, especially around correctness of CMS signature verification and additional TSA provider profiles, are welcome.
