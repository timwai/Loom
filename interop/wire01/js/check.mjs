// WIRE-01 independently implemented, dependency-free Node CBOR validator.
// Canonical event framing and signing bytes ONLY; never authorizes a Peer.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const ROOT = process.argv[2] ?? '.';
const hex = (name) => Buffer.from(
  readFileSync(join(ROOT, 'test-vectors', 'wire-v1', name), 'utf8').trim(), 'hex'
);
const MAX = 64 * 1024;
const PAYLOAD = 60 * 1024;
const DOMAIN = Buffer.from('LOOM:SECURITY-EVENT:V1\0', 'ascii');
function readStrict(bytes) {
  if (bytes.length > MAX) throw Error('oversized event');
  let pos = 0;
  const take = (n) => {
    if (!Number.isSafeInteger(n) || n < 0 || n > bytes.length - pos)
      throw Error('truncated or overflow');
    const s = bytes.subarray(pos, pos + n);
    pos += n;
    return s;
  };
  const head = (major) => {
    const byte = take(1)[0];
    if (byte >>> 5 !== major) throw Error('major type');
    const info = byte & 31;
    if (info < 24) return BigInt(info);
    if (info > 27) throw Error('indefinite/reserved');
    const n = 1 << (info - 24);
    const data = take(n);
    let value = 0n;
    for (const part of data) value = (value << 8n) | BigInt(part);
    const floors = {24:24n,25:256n,26:65536n,27:4294967296n};
    if (value < floors[info]) throw Error('nonminimal CBOR');
    return value;
  };
  const uint = () => head(0);
  const bin = (limit) => {
    const n = head(2);
    if (n > BigInt(limit)) throw Error('binary length');
    return take(Number(n));
  };
  if (head(5) !== 9n) throw Error('field count');
  let issued=0n, expires=0n;
  for (let i=0n; i<9n; i++) {
    if (uint() !== i) throw Error('map key order');
    switch (i) {
      case 0n: if (uint() !== 1n) throw Error('version'); break;
      case 1n: {
        const kind=uint();
        if (kind < 1n || kind > 5n) throw Error('kind');
        break;
      }
      case 2n: if (bin(16).length !== 16) throw Error('Space'); break;
      case 3n: if (bin(32).length !== 32) throw Error('signer'); break;
      case 4n: case 7n: uint(); break;
      case 5n: issued=uint(); break;
      case 6n: expires=uint(); break;
      case 8n: bin(PAYLOAD); break;
    }
  }
  if (pos !== bytes.length) throw Error('trailing bytes');
  if (issued >= expires) throw Error('invalid lifetime');
}
function transcript(bytes) {
  readStrict(bytes);
  const size=Buffer.alloc(4);
  size.writeUInt32BE(bytes.length);
  return Buffer.concat([DOMAIN,size,bytes]);
}
const wire=hex('event-01.cbor.hex');
const signing=hex('event-01.signing.hex');
assert.deepEqual(transcript(wire),signing);
for (let n=0;n<wire.length;n++) {
  assert.throws(()=>readStrict(wire.subarray(0,n)),undefined,'truncation '+n);
}
const negatives=new Map();
const changed=(name,index,byte)=> {
  const x=Buffer.from(wire);
  x[index]=byte;
  negatives.set(name,x);
};
changed('indefinite map',0,0xbf);
changed('extra map entry',0,0xaa);
changed('duplicate key',3,0);
changed('unsupported version',2,2);
changed('unsupported kind',4,7);
changed('tag',0,0xc9);
changed('bad signer length',25,0x1f);
negatives.set('trailing',Buffer.concat([wire,Buffer.from([0])]));
negatives.set('overlong version',Buffer.concat([wire.subarray(0,2),Buffer.from([0x18,0x01]),wire.subarray(3)]));
for (const [name,bad] of negatives) {
  assert.throws(()=>readStrict(bad),undefined,name);
}
console.log(`WIRE-01 JavaScript PASS: canonical golden transcript, ${wire.length} truncations and ${negatives.size} negative cases`);
