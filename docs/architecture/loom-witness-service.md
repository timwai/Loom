# Loom Remote Witness Service (L-002F)

This package adds a runnable TLS RPC service for one Root-authorized Witness:

- loom-witnessd opens one WitnessLog and owns exactly one Witness signing key.
- TLS 1.3 server authentication uses an Ed25519 certificate whose subject public key must equal that Witness signing key.
- The TLS certificate is pinned by the client out-of-band and checked against the same Witness public key pinned in the Root-signed resource manifest.
- Append messages carry the exact Owner-signed SignedAppend bytes. The server validates and durably appends them using its own clock.
- Observation messages carry a fresh challenge. The server signs its own current high-water state and the exact challenge.
- The client coordinator still requires both Witnesses to agree after a fresh read. A single successful append RPC is not quorum success.

## Provisioning files

The daemon reads binary files; it does not accept a Root pin or signing key from an RPC peer.

| File | Encoding |
|---|---|
| root-pin.bin | ExternallyPinnedRootForSpike::encode(): LOOM:ROOT-PIN:V1 domain, 16-byte Space ID, 32-byte Root public key, 8-byte big-endian Root epoch |
| resource-trust.bin | SignedResourceTrust::encode(): Root trust transcript followed by its 64-byte Ed25519 signature |
| witness-seed.bin | Exactly 32 raw bytes of Ed25519 seed for this Witness |
| tls-cert.der | DER X.509 certificate with Ed25519 subject key equal to the Witness public key and SAN loom-witness.local |
| tls-key.pk8.der | PKCS#8 DER private key corresponding to the certificate and Witness seed |
| witness.sqlite | One Witness's local durable log; never shared with the other Witness |

The signed resource manifest must list two distinct Witness public keys. Each daemon receives only its own seed and its own database. Provision the two instances on separately administered hosts, with separate credentials and backups. Do not copy one Witness database over the other.

## Start one Witness

Create a new database only during deliberate enrollment:

\`\`\`sh
cargo run --locked -p loom-witness --bin loom-witnessd -- \
  --bind 0.0.0.0:9443 \
  --database /var/lib/loom-witness/witness.sqlite \
  --root-pin /etc/loom-witness/root-pin.bin \
  --manifest /etc/loom-witness/resource-trust.bin \
  --witness-seed /etc/loom-witness/witness-seed.bin \
  --tls-cert /etc/loom-witness/tls-cert.der \
  --tls-key /etc/loom-witness/tls-key.pk8.der \
  --initialize
\`\`\`

Subsequent starts omit --initialize. Initialization uses create-new semantics and will not replace an existing database. The default listener is 127.0.0.1:9443; specify an externally reachable bind address only when the host firewall and network policy are configured.

Run the second Witness with its own key, certificate, database path, and the same Root-signed manifest.

## Client wiring

\`\`\`rust
use std::{net::SocketAddr, time::Duration};
use loom_witness::TlsWitnessEndpoint;

// expected_witness_key must come from the verified Root-signed manifest.
// certificate_der must be provisioned independently and match that key.
let endpoint = TlsWitnessEndpoint::new(
    "192.0.2.10:9443".parse::<SocketAddr>()?,
    certificate_der,
    expected_witness_key,
    Duration::from_secs(5),
)?;
\`\`\`

Pass two endpoints, in the exact order of the Root-signed manifest, to WitnessQuorumClient::new. Its write path sends the identical Owner-signed event to both and confirms only with a fresh two-Witness read.

## RPC framing

Every TLS connection carries one length-prefixed frame (the existing canonical bounded Loom varint framing), one request, one response, then closes.

- Request magic: LWR1.
- Response magic: LWS1.
- Operations: append (1) and challenge-bound observation (2).
- Observation responses encode the Witness key ID, complete challenge, generation, complete high-water tuple, and 64-byte signature.
- Frames are bounded by loom-wire::MAX_FRAME_BYTES; the server caps concurrent connections and applies read/write timeouts.

## Security boundary

This is a real remote TLS RPC process and a durable per-process SQLite log. It is **not** proof of physical host independence, hardware-backed monotonic storage, protection against an operator restoring that Witness's own database, or production ServiceOpen authorization. TLS authenticates the server identity; Owner signatures authorize append content; two independently pinned Witness signatures confirm quorum state. These are separate checks.

The service intentionally does not add client-certificate authentication: append requests are independently Owner-signed, and observation responses are signed by the Witness. Deploy behind an appropriate firewall, enforce connection limits at the host/network edge, protect seed and TLS private-key files, and use separate operators/hosts for the two Witnesses. No secret or private key is logged.
