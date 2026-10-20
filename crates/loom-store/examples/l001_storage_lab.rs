//! L-001 laboratory only. Public, deterministic test keys and logical fixture time.
//! SQLite restart integrity is not independent rollback resistance or power-loss proof.
use ed25519_dalek::{Signer, SigningKey};
use loom_crypto::{
    owner_authority::{
        OwnerVerifiedRevocation, ProvisionedOwnerForSpike, issuer_key_id,
        verify_owner_delegated_revocation_for_spike,
    },
    space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        VerifiedResourceTrust, trust_manifest_transcript, verify_resource_trust_for_spike,
    },
    witness_checkpoint::{TrustedWitnessForSpike, append_revocation_root},
};
use loom_store::{
    challenge_witness_quorum::{
        QuorumChallenge, QuorumHighWater, QuorumObservation, SignedQuorumObservation,
        quorum_observation_transcript,
    },
    unified_policy_journal::{ChallengeBoundRecoveryRequest, NewPolicyEvent, UnifiedPolicyJournal},
};
use loom_types::{ResourceId, SpaceId};
use loom_wire::security_event::{
    CanonicalSecurityEvent, EventKind, decode_security_event, encode_security_event, signing_input,
};
use std::{hint::black_box, io::Write, path::PathBuf, time::Instant};

fn pin() -> ExternallyPinnedRootForSpike {
    ExternallyPinnedRootForSpike {
        space: SpaceId::from_bytes([1; 16]),
        public_key: SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
        key_epoch: 7,
    }
}
fn genesis() -> VerifiedResourceTrust {
    let manifest = ResourceTrustManifest {
        space: pin().space,
        resource: ResourceId::from_bytes([2; 16]),
        owner_public_key: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
        owner_key_epoch: 3,
        witness_public_keys: [21, 22].map(|seed| {
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
        }),
        writer_epoch: 1,
        root_key_epoch: 7,
        issued_at_ms: 100,
        expires_at_ms: 300,
    };
    let signed = SignedResourceTrust {
        manifest,
        signature: SigningKey::from_bytes(&[30; 32])
            .sign(&trust_manifest_transcript(&manifest))
            .to_bytes(),
    };
    verify_resource_trust_for_spike(&pin(), &signed, 150).unwrap()
}
fn event(
    kind: EventKind,
    signer: [u8; 32],
    epoch: u64,
    seq: u64,
    payload: Vec<u8>,
) -> CanonicalSecurityEvent {
    CanonicalSecurityEvent {
        kind,
        space_id: *pin().space.as_bytes(),
        signer_key_id: issuer_key_id(&signer),
        issuer_epoch: epoch,
        issued_at_ms: 120,
        expires_at_ms: 250,
        seq,
        payload,
    }
}
fn revoke(seq: u64) -> OwnerVerifiedRevocation {
    let owner = SigningKey::from_bytes(&[11; 32]);
    let delegate = SigningKey::from_bytes(&[12; 32]);
    let public_key = delegate.verifying_key().to_bytes();
    let resource = ResourceId::from_bytes([2; 16]);
    let mut grant_payload = resource.as_bytes().to_vec();
    grant_payload.extend_from_slice(&public_key);
    grant_payload.extend_from_slice(&issuer_key_id(&public_key));
    grant_payload.push(1);
    grant_payload.extend_from_slice(&4u64.to_be_bytes());
    let grant = encode_security_event(&event(
        EventKind::OwnerGrant,
        owner.verifying_key().to_bytes(),
        3,
        1,
        grant_payload,
    ))
    .unwrap();
    let mut revoke_payload = resource.as_bytes().to_vec();
    revoke_payload.extend_from_slice(&[5; 32]);
    revoke_payload.push(3);
    let revoke = encode_security_event(&event(
        EventKind::Revocation,
        public_key,
        4,
        seq,
        revoke_payload,
    ))
    .unwrap();
    verify_owner_delegated_revocation_for_spike(
        &ProvisionedOwnerForSpike {
            space_id: pin().space,
            resource_id: resource,
            public_key: owner.verifying_key().to_bytes(),
            current_key_epoch: 3,
        },
        &grant,
        &owner.sign(&signing_input(&grant).unwrap()).to_bytes(),
        &revoke,
        &delegate.sign(&signing_input(&revoke).unwrap()).to_bytes(),
        150,
    )
    .unwrap()
}
fn metric(name: &str, samples: &[f64]) -> String {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let p95 = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    format!(
        "{{\"name\":\"{name}\",\"unit\":\"ms\",\"n\":{},\"median\":{},\"p95\":{},\"samples\":{samples:?}}}",
        sorted.len(),
        sorted[sorted.len() / 2],
        sorted[p95]
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err("invalid laboratory hex length".into());
    }
    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}
fn challenge(nonce: [u8; 32]) -> QuorumChallenge {
    let trust = genesis();
    QuorumChallenge {
        nonce,
        expected_space: trust.space(),
        expected_resource: trust.resource(),
        expected_writer_epoch: trust.writer_epoch(),
    }
}
// This fixed-scope laboratory envelope is NOT a protocol wire format. Scope
// comes from the externally fixed fixture manifest, never an untrusted reply.
fn encode_receipt(reply: SignedQuorumObservation) -> String {
    let obs = reply.observation;
    let state = obs.high_water;
    hex(&[
        reply.witness_key_id.as_slice(),
        &obs.challenge.nonce,
        &obs.generation.to_be_bytes(),
        &state.sequence.to_be_bytes(),
        &state.policy_head,
        &state.revocation_root,
        &reply.signature,
    ]
    .concat())
}
fn decode_receipt(encoded: &str) -> Result<SignedQuorumObservation, Box<dyn std::error::Error>> {
    let bytes = unhex::<208>(encoded)?;
    let trust = genesis();
    Ok(SignedQuorumObservation {
        witness_key_id: bytes[0..32].try_into()?,
        observation: QuorumObservation {
            challenge: challenge(bytes[32..64].try_into()?),
            generation: u64::from_be_bytes(bytes[64..72].try_into()?),
            high_water: QuorumHighWater {
                space: trust.space(),
                resource: trust.resource(),
                writer_epoch: trust.writer_epoch(),
                sequence: u64::from_be_bytes(bytes[72..80].try_into()?),
                policy_head: bytes[80..112].try_into()?,
                revocation_root: bytes[112..144].try_into()?,
            },
        },
        signature: bytes[144..208].try_into()?,
    })
}
fn witness_read(
    journal: &UnifiedPolicyJournal,
    sequence: u64,
    policy_head: [u8; 32],
    seed: u8,
    nonce: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    // Only the fixture's revoke-only journals are supported. The core recovery
    // method independently computes this accumulator inside its replay txn.
    let mut revocation_root = [0; 32];
    for entry in journal
        .pending_outbox()
        .map_err(|e| format!("outbox: {e:?}"))?
    {
        if entry.kind != 1 {
            return Err("fixture must contain revocations only".into());
        }
        revocation_root = append_revocation_root(revocation_root, entry.sequence, &entry.evidence)
            .ok_or("invalid revocation evidence")?;
    }
    let trust = genesis();
    let observation = QuorumObservation {
        challenge: challenge(nonce),
        generation: sequence,
        high_water: QuorumHighWater {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            sequence,
            policy_head,
            revocation_root,
        },
    };
    let key = SigningKey::from_bytes(&[seed; 32]);
    let reply = SignedQuorumObservation {
        witness_key_id: TrustedWitnessForSpike::from_public_key(key.verifying_key().to_bytes())
            .key_id,
        observation,
        signature: key
            .sign(&quorum_observation_transcript(&observation))
            .to_bytes(),
    };
    println!(
        "{{\"receipt\":\"{}\",\"sequence\":{sequence},\"pid\":{}}}",
        encode_receipt(reply),
        std::process::id()
    );
    Ok(())
}
fn codec() {
    let mut metrics = Vec::new();
    for size in [256, 4096, 60 * 1024] {
        let e = event(EventKind::Revocation, [11; 32], 1, 1, vec![77; size]);
        let encoded = encode_security_event(&e).unwrap();
        assert_eq!(decode_security_event(&encoded).unwrap(), e);
        let iterations = if size < 8192 { 20_000 } else { 2_000 };
        for (operation, decode) in [("encode", false), ("decode", true)] {
            let mut samples = Vec::new();
            // One discarded batch warms allocations/code; 10 recorded batches.
            for batch in 0..11 {
                let start = Instant::now();
                for _ in 0..iterations {
                    if decode {
                        black_box(decode_security_event(black_box(&encoded)).unwrap());
                    } else {
                        black_box(encode_security_event(black_box(&e)).unwrap());
                    }
                }
                if batch > 0 {
                    samples.push(start.elapsed().as_secs_f64() * 1000.0 / iterations as f64);
                }
            }
            metrics.push(metric(
                &format!("codec_{operation}_payload_{size}"),
                &samples,
            ));
        }
    }
    let mut durations = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        for seq in 1..=100 {
            black_box(revoke(seq));
        }
        durations.push(start.elapsed().as_secs_f64() * 10.0);
    }
    metrics.push(metric(
        "sign_encode_verify_delegated_revocation",
        &durations,
    ));
    println!(
        "{{\"metrics\":[{}],\"codec_samples_are_batch_means\":true}}",
        metrics.join(",")
    );
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).ok_or(
        "usage: l001_storage_lab codec|fill|writer|inspect|bench|witness-read|recover [DB] [ARGS]",
    )?;
    if mode == "codec" {
        codec();
        return Ok(());
    }
    if ![
        "fill",
        "writer",
        "inspect",
        "bench",
        "witness-read",
        "recover",
    ]
    .contains(&mode.as_str())
    {
        return Err("unknown storage laboratory mode".into());
    }
    let path = PathBuf::from(args.get(2).ok_or("missing database path")?);
    let journal = UnifiedPolicyJournal::open(path).map_err(|e| format!("open: {e:?}"))?;
    let genesis = genesis();
    let initial = journal
        .inspect(pin(), genesis)
        .map_err(|e| format!("inspect: {e:?}"))?;
    if !initial.admission_paused {
        return Err("admission unexpectedly enabled".into());
    }
    if mode == "witness-read" {
        return witness_read(
            &journal,
            initial.sequence,
            initial.policy_head,
            args.get(3).ok_or("missing fixture signer seed")?.parse()?,
            unhex(args.get(4).ok_or("missing nonce")?)?,
        );
    }
    if mode == "recover" {
        let nonce = unhex(args.get(3).ok_or("missing nonce")?)?;
        let replies = args[4..]
            .iter()
            .map(|s| decode_receipt(s))
            .collect::<Result<Vec<_>, _>>()?;
        let verified = journal
            .inspect_challenge_bound_recovery(ChallengeBoundRecoveryRequest {
                root: pin(),
                genesis,
                challenge: challenge(nonce),
                replies: &replies,
                minimum_generation: 1,
                now_ms: 150,
            })
            .map_err(|e| format!("guarded recovery refused: {e:?}"))?;
        println!(
            "{{\"sequence\":{},\"admission_paused\":true,\"fresh_quorum_checked\":true,\"diagnostic_only\":true}}",
            verified.high_water().sequence
        );
        return Ok(());
    }
    if mode == "inspect" {
        println!(
            "{{\"sequence\":{},\"admission_paused\":true,\"pending\":{}}}",
            initial.sequence,
            journal
                .pending_outbox()
                .map_err(|e| format!("outbox: {e:?}"))?
                .len()
        );
        return Ok(());
    }
    let count = if mode == "writer" {
        1_000_000
    } else {
        args.get(3)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(100_u64)
    };
    let mut append = Vec::new();
    for seq in initial.sequence + 1..=initial.sequence + count {
        let signed = revoke(seq);
        let start = Instant::now();
        let snapshot = journal
            .append(pin(), genesis, NewPolicyEvent::Revoke(&signed))
            .map_err(|e| format!("append: {e:?}"))?;
        assert!(snapshot.admission_paused);
        assert_eq!(snapshot.sequence, seq);
        append.push(start.elapsed().as_secs_f64() * 1000.0);
        if mode == "writer" {
            println!("ACK {seq}");
            std::io::stdout().flush()?;
        }
    }
    if mode == "bench" {
        let mut replay = Vec::new();
        for _ in 0..20 {
            let start = Instant::now();
            let snapshot = journal
                .inspect(pin(), genesis)
                .map_err(|e| format!("replay: {e:?}"))?;
            assert_eq!(snapshot.sequence, initial.sequence + count);
            assert!(snapshot.admission_paused);
            replay.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        println!(
            "{{\"metrics\":[{},{}],\"append_first_ms\":{},\"append_last_ms\":{},\"history_length\":{}}}",
            metric("signed_journal_append_full_history_replay", &append),
            metric("signed_journal_inspect", &replay),
            append[0],
            append[append.len() - 1],
            initial.sequence + count
        );
    } else if mode != "writer" {
        println!(
            "{{\"sequence\":{},\"admission_paused\":true}}",
            initial.sequence + count
        );
    }
    Ok(())
}
