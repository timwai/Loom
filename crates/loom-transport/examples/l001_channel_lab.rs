//! Explicitly invoked L-001 laboratory tool, never linked into loomd.
//! Test certificates + a fixture allowlist are NOT signed membership or Owner ACLs.
use loom_crypto::CryptoError;
use loom_identity::{MembershipVerifier, PeerPrincipal};
use loom_transport::secure_channel::{
    LocalTlsIdentity, PinnedPeer, SecurePeerContext, SecurePeerError, accept, connect,
};
use loom_types::SpaceId;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use std::{error::Error, fs, io::Write, path::Path, sync::Arc, time::Instant};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::{Duration, timeout},
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

type AnyError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;
const CANARY: &[u8] = b"LOOM-L001-PLAINTEXT-CANARY-DO-NOT-EXPOSE";
const CHUNK: usize = 64 * 1024;
const BULK: usize = 32 * 1024 * 1024;
const LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
struct Fixture {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}
impl Fixture {
    fn load(dir: &Path, name: &str) -> Result<Self> {
        Ok(Self {
            cert: fs::read(dir.join(format!("{name}.der")))?.into(),
            key: fs::read(dir.join(format!("{name}.key")))?,
        })
    }
    fn identity(&self, epoch: u64) -> LocalTlsIdentity {
        LocalTlsIdentity {
            certificate: self.cert.clone(),
            private_key: PrivateKeyDer::Pkcs8(self.key.clone().into()),
            key_epoch: epoch,
        }
    }
    fn pin(&self) -> PinnedPeer {
        PinnedPeer::new(self.cert.clone(), 1).expect("valid laboratory certificate")
    }
}

struct FixtureMembership {
    peer: PinnedPeer,
    space: SpaceId,
    deny: bool,
}
impl MembershipVerifier for FixtureMembership {
    fn verify_membership(&self, principal: &PeerPrincipal) -> std::result::Result<(), CryptoError> {
        if !self.deny
            && principal.peer_id == self.peer.peer_id
            && principal.membership_epoch == self.peer.key_epoch
            && principal.space_id == self.space
        {
            Ok(())
        } else {
            Err(CryptoError::InvalidIdentity)
        }
    }
}
fn space() -> SpaceId {
    SpaceId::from_bytes([91; 16])
}
fn context(peer: &Fixture, wrong_space: bool) -> SecurePeerContext {
    SecurePeerContext {
        expected_remote: peer.pin(),
        space_id: if wrong_space {
            SpaceId::from_bytes([92; 16])
        } else {
            space()
        },
    }
}
fn pattern() -> Vec<u8> {
    (0..CHUNK).map(|i| CANARY[i % CANARY.len()]).collect()
}
fn fixtures(dir: &Path) -> Result<()> {
    // Refuse reuse/overwrite of an arbitrary pre-existing directory.
    fs::create_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    for name in ["client", "server", "rogue"] {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let cert = CertificateParams::new(vec!["loom-peer.local".to_owned()])?.self_signed(&key)?;
        for (suffix, bytes) in [("der", cert.der().to_vec()), ("key", key.serialize_der())] {
            let path = dir.join(format!("{name}.{suffix}"));
            fs::write(&path, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    println!("{{\"fixture_created\":true,\"production_credentials\":false}}");
    Ok(())
}

async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    let data = pattern();
    loop {
        let op = stream.read_u8().await?;
        if op == 0 {
            return Ok(());
        }
        let len = stream.read_u64().await?;
        if len == 0 || len > LIMIT {
            return Err("invalid bounded lab request".into());
        }
        match op {
            1 => {
                if len > 4096 {
                    return Err("oversized lab ping".into());
                }
                let mut bytes = vec![0; len as usize];
                stream.read_exact(&mut bytes).await?;
                stream.write_all(&bytes).await?;
            }
            2 => {
                let mut left = len as usize;
                while left > 0 {
                    let count = left.min(CHUNK);
                    stream.write_all(&data[..count]).await?;
                    left -= count;
                }
            }
            3 => {
                let mut left = len as usize;
                let mut buffer = vec![0; CHUNK];
                while left > 0 {
                    let count = left.min(CHUNK);
                    stream.read_exact(&mut buffer[..count]).await?;
                    if buffer[..count] != data[..count] {
                        return Err("payload mismatch".into());
                    }
                    left -= count;
                }
                stream.write_u64(len).await?;
            }
            _ => return Err("unknown lab operation".into()),
        }
        stream.flush().await?;
    }
}
async fn server(address: &str, dir: &Path) -> Result<()> {
    let local = Fixture::load(dir, "server")?;
    let peer = Fixture::load(dir, "client")?;
    let listener = TcpListener::bind(address).await?;
    let slots = Arc::new(Semaphore::new(64));
    println!(
        "{{\"listening\":\"{}\",\"lab_only\":true}}",
        listener.local_addr()?
    );
    std::io::stdout().flush()?;
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (socket, _) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let (local, peer) = (local.clone(), peer.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _bounded = timeout(Duration::from_secs(30), async move {
                let ledger = FixtureMembership {
                    peer: peer.pin(),
                    space: space(),
                    deny: false,
                };
                match accept(socket, local.identity(1), context(&peer, false), &ledger).await {
                    Ok(mut channel) => {
                        if let Err(error) = serve_stream(channel.stream_mut()).await {
                            eprintln!("lab stream ended: {error}");
                        }
                    }
                    Err(error) => eprintln!("lab association rejected: {error:?}"),
                }
            })
            .await;
        });
    }
}

async fn dial(address: &str, dir: &Path) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
    let local = Fixture::load(dir, "client")?;
    let peer = Fixture::load(dir, "server")?;
    let socket = TcpStream::connect(address).await?;
    socket.set_nodelay(true)?;
    let ledger = FixtureMembership {
        peer: peer.pin(),
        space: space(),
        deny: false,
    };
    let channel = connect(socket, local.identity(1), context(&peer, false), &ledger)
        .await
        .map_err(|error| format!("association failed: {error:?}"))?;
    let stream = channel.into_inner();
    if stream.get_ref().1.protocol_version() != Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
    {
        return Err("laboratory requires negotiated TLS 1.3".into());
    }
    Ok(stream)
}
async fn ping<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    let bytes: Vec<_> = (0..1024).map(|i| CANARY[i % CANARY.len()]).collect();
    stream.write_u8(1).await?;
    stream.write_u64(bytes.len() as u64).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let mut received = vec![0; bytes.len()];
    stream.read_exact(&mut received).await?;
    if received != bytes {
        return Err("ping corruption".into());
    }
    Ok(())
}
async fn transfer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    len: usize,
    upload: bool,
) -> Result<()> {
    let data = pattern();
    let mut buffer = vec![0; CHUNK];
    stream.write_u8(if upload { 3 } else { 2 }).await?;
    stream.write_u64(len as u64).await?;
    stream.flush().await?;
    let mut left = len;
    while left > 0 {
        let count = left.min(CHUNK);
        if upload {
            stream.write_all(&data[..count]).await?;
        } else {
            stream.read_exact(&mut buffer[..count]).await?;
            if buffer[..count] != data[..count] {
                return Err("download corruption".into());
            }
        }
        left -= count;
    }
    if upload {
        stream.flush().await?;
        if stream.read_u64().await? != len as u64 {
            return Err("upload not acknowledged".into());
        }
    }
    Ok(())
}
fn metric(name: &str, unit: &str, samples: &[f64]) -> String {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let p95 = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    format!(
        "{{\"name\":\"{name}\",\"unit\":\"{unit}\",\"n\":{},\"median\":{},\"p95\":{},\"min\":{},\"max\":{},\"samples\":{samples:?}}}",
        sorted.len(),
        sorted[sorted.len() / 2],
        sorted[p95],
        sorted[0],
        sorted[sorted.len() - 1]
    )
}
async fn benchmark(address: &str, dir: &Path) -> Result<()> {
    for _ in 0..5 {
        dial(address, dir).await?.write_u8(0).await?;
    }
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let mut stream = dial(address, dir).await?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
        stream.write_u8(0).await?;
    }
    let mut metrics = vec![metric("tcp_tls_association", "ms", &samples)];
    let mut stream = dial(address, dir).await?;
    for _ in 0..20 {
        ping(&mut stream).await?;
    }
    samples.clear();
    for _ in 0..200 {
        let start = Instant::now();
        ping(&mut stream).await?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    metrics.push(metric("echo_1024_bytes", "ms", &samples));
    for upload in [false, true] {
        transfer(&mut stream, BULK, upload).await?;
        samples.clear();
        for _ in 0..5 {
            let start = Instant::now();
            transfer(&mut stream, BULK, upload).await?;
            samples.push(BULK as f64 / 1048576.0 / start.elapsed().as_secs_f64());
        }
        metrics.push(metric(
            if upload {
                "upload_32_mib"
            } else {
                "download_32_mib"
            },
            "MiB/s",
            &samples,
        ));
    }
    stream.write_u8(0).await?;
    let mut workers = Vec::new();
    // Measure eight established channels together; connection setup is excluded.
    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let (start_signal, start_receiver) = tokio::sync::watch::channel(false);
    for _ in 0..8 {
        let mut start_receiver = start_receiver.clone();
        let (address, dir, barrier) = (address.to_owned(), dir.to_owned(), barrier.clone());
        workers.push(tokio::spawn(async move {
            let mut stream = dial(&address, &dir).await?;
            barrier.wait().await;
            start_receiver.wait_for(|started| *started).await?;
            transfer(&mut stream, 8 * 1024 * 1024, true).await?;
            stream.write_u8(0).await?;
            Ok::<_, AnyError>(())
        }));
    }
    barrier.wait().await;
    let start = Instant::now();
    start_signal.send(true)?;
    for worker in workers {
        worker.await??;
    }
    metrics.push(metric(
        "upload_eight_channels_64_mib_total",
        "MiB/s",
        &[64.0 / start.elapsed().as_secs_f64()],
    ));
    println!(
        "{{\"lab_only\":true,\"payload_verified\":true,\"metrics\":[{}]}}",
        metrics.join(",")
    );
    Ok(())
}
async fn rejections(address: &str, dir: &Path) -> Result<()> {
    let local = Fixture::load(dir, "client")?;
    let server = Fixture::load(dir, "server")?;
    let rogue = Fixture::load(dir, "rogue")?;
    let mut cases = Vec::new();
    for case in [
        "wrong_server_pin",
        "untrusted_client",
        "wrong_space",
        "wrong_epoch",
        "membership_denied",
    ] {
        // A TCP failure or timeout is a laboratory failure, never a passing refusal.
        let socket = TcpStream::connect(address).await?;
        socket.set_nodelay(true)?;
        let peer = if case == "wrong_server_pin" {
            &rogue
        } else {
            &server
        };
        let identity = if case == "untrusted_client" {
            &rogue
        } else {
            &local
        };
        let ledger = FixtureMembership {
            peer: peer.pin(),
            space: context(peer, case == "wrong_space").space_id,
            deny: case == "membership_denied",
        };
        let result = timeout(
            Duration::from_secs(10),
            connect(
                socket,
                identity.identity(if case == "wrong_epoch" { 2 } else { 1 }),
                context(peer, case == "wrong_space"),
                &ledger,
            ),
        )
        .await?;
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err(format!("unexpected acceptance: {case}").into()),
        };
        let expected = match case {
            "membership_denied" => error == SecurePeerError::UntrustedMembership,
            "wrong_space" => matches!(
                error,
                SecurePeerError::InvalidSpace | SecurePeerError::HandshakeFailed
            ),
            "wrong_epoch" => matches!(
                error,
                SecurePeerError::InvalidEpoch | SecurePeerError::HandshakeFailed
            ),
            _ => error == SecurePeerError::HandshakeFailed,
        };
        if !expected {
            return Err(format!("wrong rejection for {case}: {error:?}").into());
        }
        cases.push(format!(
            "{{\"case\":\"{case}\",\"rejected\":true,\"error\":\"{error:?}\"}}"
        ));
    }
    println!("{{\"negative_cases\":[{}]}}", cases.join(","));
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "fixture" {
        return fixtures(Path::new(&args[2]));
    }
    if args.len() != 4 {
        return Err(
            "usage: l001_channel_lab fixture DIR | server|bench|rejections|probe ADDRESS DIR"
                .into(),
        );
    }
    let (mode, address, dir) = (&*args[1], &*args[2], Path::new(&args[3]));
    if mode == "server" {
        return server(address, dir).await;
    }
    timeout(Duration::from_secs(120), async {
        match mode {
            "bench" => benchmark(address, dir).await,
            "rejections" => rejections(address, dir).await,
            "probe" => {
                let mut stream = dial(address, dir).await?;
                ping(&mut stream).await?;
                stream.write_u8(0).await?;
                println!("{{\"authenticated_echo\":true}}");
                Ok(())
            }
            _ => Err("unknown laboratory mode".into()),
        }
    })
    .await?
}
