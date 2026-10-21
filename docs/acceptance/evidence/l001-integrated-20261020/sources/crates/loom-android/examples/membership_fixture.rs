//! Public, disposable laboratory keys. Never enroll these as production pins.
use ed25519_dalek::{Signer, SigningKey};
use loom_crypto::{membership::*, owner_authority::issuer_key_id};
use loom_types::SpaceId;
use loom_wire::security_event::{
    CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(std::env::args().nth(1).ok_or("output directory required")?);
    fs::create_dir_all(&dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let root = SigningKey::from_bytes(&[111; 32]);
    let writer = SigningKey::from_bytes(&[112; 32]);
    let member = SigningKey::from_bytes(&[113; 32]);
    let d = MembershipWriterDelegation {
        space: SpaceId::from_bytes([81; 16]),
        root_epoch: 1,
        writer_public_key: writer.verifying_key().to_bytes(),
        writer_epoch: 3,
        issued_at_ms: now - 1000,
        expires_at_ms: now + 3_600_000,
    };
    let event = CanonicalSecurityEvent {
        kind: EventKind::MembershipGrant,
        space_id: *d.space.as_bytes(),
        signer_key_id: issuer_key_id(&d.writer_public_key),
        issuer_epoch: 3,
        issued_at_ms: now - 500,
        expires_at_ms: now + 1_800_000,
        seq: 7,
        payload: membership_payload(member.verifying_key().to_bytes(), 4, 19),
    };
    let bytes = encode_security_event(&event).map_err(|e| format!("{e:?}"))?;
    let mut envelope = root.verifying_key().to_bytes().to_vec();
    envelope.extend_from_slice(&d.root_epoch.to_be_bytes());
    envelope.extend_from_slice(d.space.as_bytes());
    envelope.extend_from_slice(&d.writer_public_key);
    envelope.extend_from_slice(&d.writer_epoch.to_be_bytes());
    envelope.extend_from_slice(&d.issued_at_ms.to_be_bytes());
    envelope.extend_from_slice(&d.expires_at_ms.to_be_bytes());
    envelope.extend_from_slice(&root.sign(&membership_writer_transcript(&d)).to_bytes());
    envelope.extend_from_slice(&d.writer_epoch.to_be_bytes());
    envelope.extend_from_slice(&event.seq.to_be_bytes());
    envelope.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&bytes);
    envelope.extend_from_slice(
        &writer
            .sign(&signing_input(&bytes).map_err(|e| format!("{e:?}"))?)
            .to_bytes(),
    );
    fs::write(dir.join("membership.bin"), &envelope)?;
    let mut expected = peer_id_for_public_key(&member.verifying_key().to_bytes())
        .digest()
        .to_vec();
    for value in [4u64, 19, 7] {
        expected.extend_from_slice(&value.to_be_bytes());
    }
    fs::write(dir.join("membership.expected"), &expected)?;
    fs::write(
        dir.join("membership.json"),
        format!(
            "{{\"lab_only\":true,\"public_fixture_keys\":true,\"generated_at_ms\":{now},\"expires_at_ms\":{},\"key_epoch\":4,\"member_epoch\":19,\"sequence\":7}}\n",
            event.expires_at_ms
        ),
    )?;
    Ok(())
}
