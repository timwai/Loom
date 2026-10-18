// Independent Node.js emitter and Ed25519 verifier for candidate L-ADR-07.
// Execute: node test-vectors/wire-v1/check.mjs
import {readFileSync} from "node:fs";
import {createHash, createPrivateKey, createPublicKey, sign, verify} from "node:crypto";

function expected(name) {
  return Buffer.from(readFileSync("test-vectors/wire-v1/" + name, "utf8").trim(), "hex");
}
function arg(major, value) {
  const n = BigInt(value), prefix = major << 5;
  if (n < 24n) return Buffer.from([prefix | Number(n)]);
  if (n <= 255n) return Buffer.from([prefix | 24, Number(n)]);
  if (n <= 65535n) {const b=Buffer.alloc(3);b[0]=prefix|25;b.writeUInt16BE(Number(n),1);return b;}
  if (n <= 4294967295n) {const b=Buffer.alloc(5);b[0]=prefix|26;b.writeUInt32BE(Number(n),1);return b;}
  const b=Buffer.alloc(9);b[0]=prefix|27;b.writeBigUInt64BE(n,1);return b;
}
const u=n=>arg(0,n);
const bytes=b=>Buffer.concat([arg(2,b.length),b]);
const space=Buffer.from(Array.from({length:16},(_,i)=>i));
const signer=Buffer.from(Array.from({length:32},(_,i)=>i+16));
const entries=[
  [0,u(1)],[1,u(3)],[2,bytes(space)],[3,bytes(signer)],[4,u(2)],
  [5,u(1710000000123n)],[6,u(1710000030123n)],[7,u(8)],
  [8,bytes(Buffer.from([0xa1,0x01,0xf5]))]
];
const encoded=Buffer.concat([arg(5,entries.length),...entries.flatMap(([k,v])=>[u(k),v])]);
function check(label, actual, reference) {
  if (!actual.equals(reference)) throw Error(label + " mismatch: " + actual.toString("hex"));
}
check("canonical CBOR",encoded,expected("event-01.cbor.hex"));
const length=Buffer.alloc(4);length.writeUInt32BE(encoded.length);
const transcript=Buffer.concat([Buffer.from("LOOM:SECURITY-EVENT:V1\0"),length,encoded]);
check("signing transcript",transcript,expected("event-01.signing.hex"));
const id=createHash("sha256").update(Buffer.from("LOOM:EVENT-ID:V1\0")).update(encoded).digest();
check("event id",id,expected("event-01.event-id.hex"));
const seed=Buffer.from(Array.from({length:32},(_,i)=>i));
const pkcs8=Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),seed]);
const privateKey=createPrivateKey({key:pkcs8,format:"der",type:"pkcs8"});
const signature=sign(null,transcript,privateKey);
check("Ed25519 signature",signature,expected("event-01.signature.hex"));
const spki=Buffer.concat([Buffer.from("302a300506032b6570032100","hex"),expected("event-01.pubkey.hex")]);
const publicKey=createPublicKey({key:spki,format:"der",type:"spki"});
if (!verify(null,transcript,publicKey,signature)) throw Error("valid signature failed");
const tampered=Buffer.from(transcript);tampered[tampered.length-1]^=1;
if (verify(null,tampered,publicKey,signature)) throw Error("tampered signature accepted");
console.log("JavaScript canonical CBOR, transcript, event id and Ed25519 signature: PASS");
