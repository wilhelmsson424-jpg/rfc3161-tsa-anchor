import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildTSQ } from '../lib/tsa.js';
import crypto from 'node:crypto';

test('buildTSQ rejects non-32-byte input', () => {
  assert.throws(() => buildTSQ(Buffer.from('too short')));
  assert.throws(() => buildTSQ(Buffer.alloc(31)));
  assert.throws(() => buildTSQ(Buffer.alloc(33)));
});

test('buildTSQ accepts a 32-byte SHA-256 digest', () => {
  const hash = crypto.createHash('sha256').update('hello').digest();
  const tsq = buildTSQ(hash);
  assert.ok(Buffer.isBuffer(tsq));
  assert.ok(tsq.length > 30);
});

test('buildTSQ output starts with ASN.1 SEQUENCE tag', () => {
  const hash = crypto.createHash('sha256').update('test').digest();
  const tsq = buildTSQ(hash);
  assert.equal(tsq[0], 0x30);
});

test('buildTSQ embeds the SHA-256 OID', () => {
  const hash = crypto.createHash('sha256').update('test').digest();
  const tsq = buildTSQ(hash);
  const oidBytes = Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
  assert.ok(tsq.includes(oidBytes));
});

test('buildTSQ embeds the input hash', () => {
  const hash = crypto.createHash('sha256').update('unique-marker-12345').digest();
  const tsq = buildTSQ(hash);
  assert.ok(tsq.includes(hash));
});
