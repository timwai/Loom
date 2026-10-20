#![cfg(feature = "experimental-lan")]
#[path = "../examples/support/l002_fixture.rs"]
mod fixture;
use fixture::*;
use loom_core::lan_read::*;
use loom_store::witness_append::*;
use loom_transport::secure_channel::*;
use std::{
    fs::{self, File},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new() -> Self {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "loom-l002-{}-{}-{}",
            std::process::id(),
            now(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn fixture(&self) -> Fixture {
        Fixture::enroll(&self.0).unwrap()
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
type Client = SecurePeerChannel<tokio_rustls::client::TlsStream<TcpStream>>;
type Server = SecurePeerChannel<tokio_rustls::server::TlsStream<TcpStream>>;
async fn pair(a: &Peer, b: &Peer) -> (Client, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    timeout(Duration::from_secs(5), async {
        let (a_ch, b_ch) = tokio::join!(
            async {
                connect(
                    TcpStream::connect(addr).await.unwrap(),
                    a.identity(),
                    b.context(),
                    &b.verifier,
                )
                .await
            },
            async {
                let (tcp, _) = listener.accept().await.unwrap();
                accept(tcp, b.identity(), a.context(), &a.verifier).await
            }
        );
        (a_ch.unwrap(), b_ch.unwrap())
    })
    .await
    .unwrap()
}
fn server(f: &Fixture) -> LanReadCandidate {
    LanReadCandidate::from_owner_file(
        f.trust,
        File::open(f.directory.join("approved.txt")).unwrap(),
        f.log("policy"),
    )
    .unwrap()
}

#[tokio::test]
async fn l002_real_tls_file_chunks_equal_owner_snapshot_and_no_write_api() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    let service = server(&f);
    let (mut client, mut channel) = pair(&a, &b).await;
    let mut session = service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            f.replies(c)
        })
        .unwrap();
    let mut received = Vec::new();
    loop {
        let bytes = service
            .read_chunk(&mut session, &channel, &a.credential, &a.verifier, 7, |c| {
                f.replies(c)
            })
            .unwrap();
        if bytes.is_empty() {
            break;
        }
        channel.stream_mut().write_all(&bytes).await.unwrap();
        let mut output = vec![0; bytes.len()];
        client.stream_mut().read_exact(&mut output).await.unwrap();
        received.extend(output);
    }
    assert_eq!(received, CONTENT);
    assert!(!loom_core::PeerCore::new().network_listening_enabled());
}

#[tokio::test]
async fn l002_signed_member_without_owner_grant_and_wrong_resource_are_refused() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    let (_, channel) = pair(&a, &b).await;
    let service = server(&f);
    assert!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| f
                .replies(c))
            .is_err()
    );
    f.commit_all(&a, true);
    assert_eq!(
        service
            .open_read(
                &channel,
                &a.credential,
                &a.verifier,
                loom_types::ResourceId::from_bytes([0; 16]),
                |c| f.replies(c)
            )
            .unwrap_err(),
        ReadError::Denied
    );
    assert_eq!(
        service
            .open_read(&channel, &b.credential, &b.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Membership
    );
}

#[tokio::test]
async fn l002_revoke_next_chunk_restart_and_regrant_never_resurrect_old_session() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    let service = server(&f);
    let (_, channel) = pair(&a, &b).await;
    let mut session = service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            f.replies(c)
        })
        .unwrap();
    assert_eq!(
        service
            .read_chunk(&mut session, &channel, &a.credential, &a.verifier, 4, |c| f
                .replies(c))
            .unwrap(),
        &CONTENT[..4]
    );
    f.commit_all(&a, false);
    assert!(
        service
            .read_chunk(&mut session, &channel, &a.credential, &a.verifier, 4, |c| f
                .replies(c))
            .is_err()
    );
    drop(service);
    let service = server(&f);
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Denied
    );
    f.commit_all(&a, true);
    assert_eq!(
        service.read_chunk(&mut session, &channel, &a.credential, &a.verifier, 4, |c| f
            .replies(c)),
        Err(ReadError::Stale)
    );
    assert!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| f
                .replies(c))
            .is_ok()
    );
}

#[tokio::test]
async fn l002_partial_quorum_and_cached_nonce_reply_refuse_then_exact_retry_recovers() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    let history = f.log("policy").history().unwrap();
    let signed = f.signed(&history, &a, true);
    f.log("policy").append(signed, now()).unwrap();
    f.log("witness-a").append(signed, now()).unwrap();
    let service = server(&f);
    let (_, channel) = pair(&a, &b).await;
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Quorum
    );
    f.log("witness-b").append(signed, now()).unwrap();
    let mut cached = Vec::new();
    service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            cached = f.replies(c)?;
            Ok(cached.clone())
        })
        .unwrap();
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |_| Ok(
                cached
            ))
            .unwrap_err(),
        ReadError::Quorum
    );
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
                let mut r = f.replies(c)?;
                r.pop();
                Ok(r)
            })
            .unwrap_err(),
        ReadError::Quorum
    );
}

#[tokio::test]
async fn l002_revocation_during_external_observation_and_membership_pause_fail_closed() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    let service = server(&f);
    let (_, channel) = pair(&a, &b).await;
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
                let old = f.replies(c)?;
                f.commit_all(&a, false);
                Ok(old)
            })
            .unwrap_err(),
        ReadError::Stale
    );
    f.commit_all(&a, true);
    let mut session = service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            f.replies(c)
        })
        .unwrap();
    a.verifier.pause().unwrap();
    assert_eq!(
        service.read_chunk(&mut session, &channel, &a.credential, &a.verifier, 4, |c| f
            .replies(c)),
        Err(ReadError::Membership)
    );
}

#[tokio::test]
async fn l002_restored_policy_backup_refused_by_latest_witnesses() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    fs::copy(f.path("policy"), f.directory.join("old.sqlite")).unwrap();
    f.commit_all(&a, false);
    fs::copy(f.directory.join("old.sqlite"), f.path("policy")).unwrap();
    let service = server(&f);
    let (_, channel) = pair(&a, &b).await;
    assert_eq!(
        service
            .open_read(&channel, &a.credential, &a.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Quorum
    );
}

#[tokio::test]
async fn l002_path_replacement_and_invalid_chunk_cannot_redirect_or_advance_cursor() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    let file = File::open(f.directory.join("approved.txt")).unwrap();
    fs::rename(
        f.directory.join("approved.txt"),
        f.directory.join("original.txt"),
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("../outside-secret", f.directory.join("approved.txt")).unwrap();
    #[cfg(not(unix))]
    fs::write(f.directory.join("approved.txt"), b"replacement secret").unwrap();
    let service = LanReadCandidate::from_owner_file(f.trust, file, f.log("policy")).unwrap();
    assert_eq!(service.snapshot_digest(), server_from_original_digest(&f));
    let (_, channel) = pair(&a, &b).await;
    let mut session = service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            f.replies(c)
        })
        .unwrap();
    for size in [0, MAX_CHUNK_BYTES + 1] {
        assert_eq!(
            service.read_chunk(
                &mut session,
                &channel,
                &a.credential,
                &a.verifier,
                size,
                |c| f.replies(c)
            ),
            Err(ReadError::InvalidInput)
        );
    }
    assert_eq!(
        service
            .read_chunk(
                &mut session,
                &channel,
                &a.credential,
                &a.verifier,
                MAX_CHUNK_BYTES,
                |c| f.replies(c)
            )
            .unwrap(),
        CONTENT
    );
}
fn server_from_original_digest(f: &Fixture) -> [u8; 32] {
    LanReadCandidate::from_owner_file(
        f.trust,
        File::open(f.directory.join("original.txt")).unwrap(),
        f.log("policy"),
    )
    .unwrap()
    .snapshot_digest()
}

#[test]
fn l002_authenticated_append_tamper_fork_stale_scope_and_restart() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let mut log = f.log("policy");
    let empty = log.history().unwrap();
    let signed = f.signed(&empty, &a, true);
    let mut tampered = signed;
    tampered.request.mutation.allow = false;
    assert_eq!(
        log.append(tampered, now()),
        Err(AppendError::InvalidSignature)
    );
    let mut wrong = signed;
    wrong.request.manifest[0] ^= 1;
    assert_eq!(log.append(wrong, now()), Err(AppendError::WrongTrust));
    let committed = log.append(signed, now()).unwrap();
    assert_eq!(log.append(signed, now()).unwrap(), committed);
    let fork = f.signed(&empty, &a, false);
    assert_eq!(
        log.append(fork, now()),
        Err(AppendError::Fork(Box::new(signed)))
    );
    drop(log);
    let mut reopened = f.log("policy");
    assert_eq!(reopened.history(), Err(AppendError::Conflict));
    assert_eq!(reopened.fork_evidence().unwrap(), vec![(signed, fork)]);
    let mut bytes = signed.encode();
    bytes.push(0);
    assert_eq!(
        SignedAppend::decode(&bytes),
        Err(AppendError::InvalidRecord)
    );
    let connection = rusqlite::Connection::open(f.path("policy")).unwrap();
    connection
        .execute("UPDATE entries SET evidence=zeroblob(5)", [])
        .unwrap();
    assert!(WitnessLog::open(&f.path("policy"), f.trust).is_err());
}

#[test]
fn l002_cross_connection_commit_is_blocked_during_bounded_read() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let mut reader = f.log("policy");
    let signed = f.signed(&reader.history().unwrap(), &a, true);
    let mut writer = f.log("policy");
    reader
        .inspect(|history| {
            assert!(history.records().is_empty());
            assert_eq!(writer.append(signed, now()), Err(AppendError::Storage));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        writer.append(signed, now()).unwrap().high_water().sequence,
        1
    );
}

#[test]
fn l002_expired_revocation_remains_during_history_replay_and_new_expired_grant_refused() {
    use ed25519_dalek::Signer;
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    f.commit_all(&a, true);
    let history = f.log("policy").history().unwrap();
    let mut revoke = f.signed(&history, &a, false);
    revoke.request.expires_at_ms = now() + 1;
    revoke.owner_signature = f.owner.sign(&append_transcript(&revoke.request)).to_bytes();
    let committed = f
        .log("policy")
        .append(revoke, revoke.request.expires_at_ms - 1)
        .unwrap();
    assert_eq!(f.log("policy").history().unwrap(), committed);
    assert!(!committed.permits(a.credential.peer(), 5, 6, revoke.request.expires_at_ms + 1));
    // A lost acknowledgement may be retried after request expiry without
    // applying the signed mutation twice (provided Root enrollment is valid).
    assert_eq!(
        f.log("policy")
            .append(revoke, revoke.request.expires_at_ms + 1)
            .unwrap(),
        committed
    );
    let mut grant = f.signed(&committed, &a, true);
    grant.request.expires_at_ms = now();
    grant.owner_signature = f.owner.sign(&append_transcript(&grant.request)).to_bytes();
    assert_eq!(
        f.log("policy").append(grant, grant.request.expires_at_ms),
        Err(AppendError::Expired)
    );
}

#[test]
fn l002_concurrent_owner_fork_is_durable_and_quarantines_both_observation_and_retry() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let history = f.log("policy").history().unwrap();
    let one = f.signed(&history, &a, true);
    let two = f.signed(&history, &a, false);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for signed in [one, two] {
        let mut log = f.log("policy");
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            log.append(signed, now())
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(AppendError::Fork(_))))
            .count(),
        1
    );
    let mut log = f.log("policy");
    assert_eq!(log.fork_evidence().unwrap().len(), 1);
    assert_eq!(log.append(one, now()), Err(AppendError::Conflict));
    let challenge = loom_store::challenge_witness_quorum::QuorumChallenge {
        nonce: [71; 32],
        expected_space: space(),
        expected_resource: resource(),
        expected_writer_epoch: f.trust.writer_epoch(),
    };
    assert!(log.observe(&f.witness_keys[0], challenge, now()).is_err());
}

#[tokio::test]
async fn l002_member_key_epoch_rotation_requires_new_owner_grant() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let old = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&old, true);
    let new = f.peer_at_epochs("a", 7, 9);
    let (_, channel) = pair(&new, &b).await;
    let service = server(&f);
    assert_eq!(
        service
            .open_read(&channel, &new.credential, &new.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Denied
    );
    assert_eq!(
        service
            .open_read(&channel, &old.credential, &new.verifier, resource(), |c| f
                .replies(c))
            .unwrap_err(),
        ReadError::Membership
    );
    f.commit_all(&new, true);
    assert!(
        service
            .open_read(&channel, &new.credential, &new.verifier, resource(), |c| f
                .replies(c))
            .is_ok()
    );
}

#[tokio::test]
async fn l002_commit_barrier_and_midflight_membership_pause_prevent_next_chunk() {
    let dir = TestDir::new();
    let f = dir.fixture();
    let a = f.peer("a");
    let b = f.peer("b");
    f.commit_all(&a, true);
    let service = server(&f);
    let (_, channel) = pair(&a, &b).await;
    let mut session = service
        .open_read(&channel, &a.credential, &a.verifier, resource(), |c| {
            f.replies(c)
        })
        .unwrap();
    assert_eq!(
        service.read_chunk(&mut session, &channel, &a.credential, &a.verifier, 4, |c| {
            let replies = f.replies(c)?;
            a.verifier.pause().unwrap();
            Ok(replies)
        }),
        Err(ReadError::Membership)
    );
    let history = f.log("policy").history().unwrap();
    let signed = f.signed(&history, &a, false);
    service.commit(signed).unwrap();
    for name in ["witness-a", "witness-b"] {
        f.log(name).append(signed, now()).unwrap();
    }
    assert!(
        !f.log("policy")
            .history()
            .unwrap()
            .permits(a.credential.peer(), 5, 6, now())
    );
}

#[test]
fn l002_missing_log_oversize_file_and_torn_record_fail_closed_without_reenrollment() {
    let dir = TestDir::new();
    let f = dir.fixture();
    assert!(WitnessLog::open(&f.path("missing"), f.trust).is_err());
    assert!(!f.path("missing").exists());
    assert!(WitnessLog::create(&f.path("policy"), f.trust).is_err());
    let path = f.directory.join("huge.txt");
    let file = File::create(&path).unwrap();
    file.set_len(MAX_FILE_BYTES as u64 + 1).unwrap();
    drop(file);
    assert!(matches!(
        LanReadCandidate::from_owner_file(f.trust, File::open(&path).unwrap(), f.log("policy")),
        Err(ReadError::InvalidInput)
    ));
    let a = f.peer("a");
    let signed = f.commit_all(&a, true);
    for length in [0, 1, SIGNED_APPEND_BYTES - 1] {
        assert_eq!(
            SignedAppend::decode(&signed.encode()[..length]),
            Err(AppendError::InvalidRecord)
        );
    }
    let mut bad = signed.encode();
    bad[0] ^= 1;
    assert_eq!(SignedAppend::decode(&bad), Err(AppendError::InvalidRecord));
}
