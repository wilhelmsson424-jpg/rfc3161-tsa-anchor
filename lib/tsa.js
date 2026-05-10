/**
 * rfc3161-tsa-anchor
 *
 * RFC 3161 Time Stamping Authority client with dual-anchor support.
 * Anchors hash values against two independent TSA providers so a single
 * provider going dark cannot break long-term verifiability.
 *
 * Default providers:
 *   Primary: freetsa.org (free, EU-based)
 *   Backup:  tsa.swisssign.net (commercial, Switzerland)
 *
 * Operational note: timestamp.digicert.com may be blocked from some
 * cloud regions due to outbound firewall policy. If you observe
 * EHOSTUNREACH against DigiCert, configure tsa.swisssign.net or
 * zeitstempel.dfn.de (TU Berlin) instead.
 *
 * Author: Wilhelmsson Labs
 * License: MIT
 */

import crypto from 'node:crypto';
import forge from 'node-forge';

/**
 * Build a TimeStampReq per RFC 3161.
 */
export function buildTSQ(hash) {
  if (hash.length !== 32) {
    throw new Error(`TSQ requires SHA-256 hash (32 bytes), got ${hash.length}`);
  }

  const asn1 = forge.asn1;
  const TimeStampReq = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true,
    [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(0x01)),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
        ]),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, hash.toString('binary')),
      ]),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)),
    ]
  );

  return Buffer.from(asn1.toDer(TimeStampReq).getBytes(), 'binary');
}

/**
 * POST a TSQ to a TSA endpoint and return the TSR.
 */
export async function postTSQ(tsaUrl, tsq) {
  const response = await fetch(tsaUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/timestamp-query',
      'Content-Length': tsq.length.toString(),
    },
    body: tsq,
  });

  if (!response.ok) {
    throw new Error(`TSA returned ${response.status}: ${await response.text()}`);
  }

  const contentType = response.headers.get('content-type');
  if (!contentType || !contentType.includes('timestamp-reply')) {
    throw new Error(`TSA returned unexpected content-type: ${contentType}`);
  }

  return Buffer.from(await response.arrayBuffer());
}

/**
 * Parse a TSR and extract the timestamp token + genTime.
 */
export function parseTSR(tsr) {
  const asn1 = forge.asn1;
  const der = forge.util.createBuffer(tsr.toString('binary'));
  const obj = asn1.fromDer(der);

  const statusInfo = obj.value[0];
  const statusValue = statusInfo.value[0].value.charCodeAt(0);

  if (statusValue !== 0 && statusValue !== 1) {
    throw new Error(`TSA rejected request, status=${statusValue}`);
  }

  if (obj.value.length < 2) {
    throw new Error('TSR is missing timeStampToken');
  }

  const timeStampToken = obj.value[1];
  const tokenDer = Buffer.from(asn1.toDer(timeStampToken).getBytes(), 'binary');

  let genTime = null;
  try {
    const signedData = timeStampToken.value[1].value[0];
    for (const element of signedData.value) {
      if (element.tagClass === 0 && element.type === 16) {
        for (const sub of element.value || []) {
          if (sub.tagClass === 2 && sub.type === 0) {
            const tstInfoOctet = sub.value[0];
            const tstInfo = asn1.fromDer(forge.util.createBuffer(tstInfoOctet.value));
            for (const field of tstInfo.value) {
              if (field.type === 24) {
                genTime = parseGeneralizedTime(field.value);
                break;
              }
            }
          }
        }
      }
    }
  } catch (e) {
    // Parsing failure is non-fatal; the token is still externally verifiable.
  }

  return { status: statusValue, token: tokenDer, genTime };
}

function parseGeneralizedTime(str) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(str);
  if (!m) return null;
  return new Date(Date.UTC(
    parseInt(m[1]), parseInt(m[2]) - 1, parseInt(m[3]),
    parseInt(m[4]), parseInt(m[5]), parseInt(m[6])
  ));
}

/**
 * Verify that the TSR refers to exactly the hash we submitted (RFC 3161 2.4.2).
 * Uses depth-limited recursive walk and constant-time comparison.
 */
export function verifyTSRMessageImprint(tsr, expectedHash) {
  const asn1 = forge.asn1;
  const der = forge.util.createBuffer(tsr.toString('binary'));
  const obj = asn1.fromDer(der);

  const timeStampToken = obj.value[1];
  if (!timeStampToken) {
    throw new Error('TSR missing timeStampToken');
  }

  let foundImprint = null;
  function findOctets(node, depth = 0) {
    if (depth > 32) return;
    if (!node || !node.value) return;
    if (Array.isArray(node.value)) {
      for (const child of node.value) findOctets(child, depth + 1);
    } else if (node.type === 4 && typeof node.value === 'string') {
      try {
        const inner = asn1.fromDer(forge.util.createBuffer(node.value));
        if (inner.type === 16 && inner.value.length >= 3) {
          const messageImprint = inner.value[2];
          if (messageImprint && messageImprint.value && messageImprint.value.length >= 2) {
            const hashedMessage = messageImprint.value[1];
            if (hashedMessage.type === 4) {
              foundImprint = Buffer.from(hashedMessage.value, 'binary');
            }
          }
        }
      } catch (e) {
        // Not TSTInfo; keep searching.
      }
    }
  }
  findOctets(timeStampToken);

  if (!foundImprint) {
    throw new Error('Could not find messageImprint in TSR');
  }

  if (foundImprint.length !== expectedHash.length || !crypto.timingSafeEqual(foundImprint, expectedHash)) {
    throw new Error(
      `TSR messageImprint mismatch. Expected ${expectedHash.toString('hex')}, got ${foundImprint.toString('hex')}`
    );
  }

  return true;
}

/**
 * Verify the TSR's CMS signature against a CA cert.
 */
export function verifyTSRSignature(tsr, caCertPem) {
  if (!caCertPem) return null;

  try {
    const asn1 = forge.asn1;
    const der = forge.util.createBuffer(tsr.toString('binary'));
    const tsrObj = asn1.fromDer(der);

    const timeStampToken = tsrObj.value[1];
    const p7 = forge.pkcs7.messageFromAsn1(timeStampToken);
    const caStore = forge.pki.createCaStore([caCertPem]);

    if (typeof p7.verify === 'function') {
      return p7.verify({ caStore });
    }

    if (p7.certificates && p7.certificates.length > 0) {
      for (const cert of p7.certificates) {
        try {
          forge.pki.verifyCertificateChain(caStore, [cert]);
          return true;
        } catch (_) {}
      }
    }
    return false;
  } catch (e) {
    throw new Error(`TSR signature verification failed: ${e.message}`);
  }
}

/**
 * Anchor a hash against a single TSA, falling back to backup on failure.
 * Includes messageImprint verification + retry with exponential backoff.
 */
export async function anchorHash(hashHex, options = {}) {
  const primaryUrl = options.primaryUrl || process.env.TSA_PRIMARY_URL || 'https://freetsa.org/tsr';
  const backupUrl = options.backupUrl || process.env.TSA_BACKUP_URL || 'https://tsa.swisssign.net/';
  const caCerts = options.caCerts || {};

  const hash = Buffer.from(hashHex, 'hex');
  const tsq = buildTSQ(hash);

  const errors = [];
  const providers = [primaryUrl, backupUrl];

  for (const url of providers) {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const tsr = await postTSQ(url, tsq);
        const parsed = parseTSR(tsr);
        verifyTSRMessageImprint(tsr, hash);

        let signatureVerified = null;
        if (caCerts[url]) {
          signatureVerified = verifyTSRSignature(tsr, caCerts[url]);
          if (signatureVerified === false) {
            throw new Error('TSR signature verification returned false');
          }
        }

        return { tsq, tsr, token: parsed.token, genTime: parsed.genTime, providerUrl: url, signatureVerified };
      } catch (e) {
        errors.push(`${url} (attempt ${attempt + 1}): ${e.message}`);
        if (attempt < 2) {
          await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
        }
      }
    }
  }

  throw new Error(`All TSA providers failed after retry: ${errors.join('; ')}`);
}

/**
 * Dual-anchor: hit BOTH providers so the timestamp survives long-term
 * even if one provider goes dark over a 7+ year retention horizon.
 * Sequential rather than parallel (rate-limit / TLS handshake friendliness).
 */
export async function anchorHashDual(hashHex, options = {}) {
  const primaryUrl = options.primaryUrl || process.env.TSA_PRIMARY_URL || 'https://freetsa.org/tsr';
  const backupUrl = options.backupUrl || process.env.TSA_BACKUP_URL || 'https://tsa.swisssign.net/';

  const hash = Buffer.from(hashHex, 'hex');
  const tsq = buildTSQ(hash);

  async function tryAnchor(url) {
    let lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const tsr = await postTSQ(url, tsq);
        verifyTSRMessageImprint(tsr, hash);
        const parsed = parseTSR(tsr);
        return { tsr, token: parsed.token, genTime: parsed.genTime, providerUrl: url };
      } catch (e) {
        lastErr = e;
        if (attempt < 1) {
          await new Promise((r) => setTimeout(r, 2000));
        }
      }
    }
    throw lastErr;
  }

  const successes = [];
  const failures = [];

  try { successes.push(await tryAnchor(primaryUrl)); }
  catch (e) { failures.push(`${primaryUrl}: ${e.message}`); }

  try { successes.push(await tryAnchor(backupUrl)); }
  catch (e) { failures.push(`${backupUrl}: ${e.message}`); }

  if (successes.length === 0) {
    throw new Error(`Both TSA providers failed: ${failures.join('; ')}`);
  }

  const totalProviders = 2;
  const partial = successes.length < totalProviders;
  if (partial) {
    console.warn(
      `[TSA] partial-anchor: ${successes.length}/${totalProviders} providers succeeded. Failures: ${failures.join('; ')}`
    );
  }

  return { tsq, anchors: successes, failures, partial };
}
