use ed25519_dalek::SigningKey;
use loom_crypto::space_trust::{
    ExternallyPinnedRootForSpike, SignedResourceTrust, verify_resource_trust_for_spike,
};
use loom_store::witness_append::WitnessLog;
use loom_witness::{WitnessRpcServer, WitnessRpcService};
use std::{
    collections::HashMap,
    env, fs,
    io,
    net::TcpListener,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Args {
    bind: String,
    database: PathBuf,
    root_pin: PathBuf,
    manifest: PathBuf,
    witness_seed: PathBuf,
    tls_certificate: PathBuf,
    tls_private_key: PathBuf,
    initialize: bool,
}

fn usage() {
    println!(
        "loom-witnessd --bind IP:PORT --database PATH --root-pin PATH --manifest PATH \\
         --witness-seed PATH --tls-cert PATH --tls-key PATH [--initialize]"
    );
    println!("Default bind: 127.0.0.1:9443. Use a firewall when binding a public interface.");
    println!("Provisioning files are binary records; see docs/architecture/loom-witness-service.md.");
}

fn parse_args() -> Result<Option<Args>, io::Error> {
    let mut values = HashMap::<String, String>::new();
    let mut initialize = false;
    let mut iter = env::args().skip(1);
    while let Some(argument) = iter.next() {
        if argument == "--help" || argument == "-h" {
            usage();
            return Ok(None);
        }
        if argument == "--initialize" {
            initialize = true;
            continue;
        }
        let value = iter.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("missing value for {argument}"))
        })?;
        if !matches!(
            argument.as_str(),
            "--bind"
                | "--database"
                | "--root-pin"
                | "--manifest"
                | "--witness-seed"
                | "--tls-cert"
                | "--tls-key"
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown argument: {argument}"),
            ));
        }
        if values.insert(argument.clone(), value).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate argument: {argument}"),
            ));
        }
    }
    let take = |key: &str| {
        values.get(key).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("required argument missing: {key}"),
            )
        })
    };
    Ok(Some(Args {
        bind: values
            .get("--bind")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:9443".to_owned()),
        database: PathBuf::from(take("--database")?),
        root_pin: PathBuf::from(take("--root-pin")?),
        manifest: PathBuf::from(take("--manifest")?),
        witness_seed: PathBuf::from(take("--witness-seed")?),
        tls_certificate: PathBuf::from(take("--tls-cert")?),
        tls_private_key: PathBuf::from(take("--tls-key")?),
        initialize,
    }))
}

fn now_ms() -> Result<u64, io::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before Unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| io::Error::other("system clock exceeds u64 milliseconds"))
}

fn invalid_data(label: &str, error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{label}: {error:?}"))
}

fn run(args: Args) -> Result<(), io::Error> {
    let root_pin_bytes = fs::read(&args.root_pin)?;
    let root_pin = ExternallyPinnedRootForSpike::decode(&root_pin_bytes)
        .map_err(|error| invalid_data("invalid root pin", error))?;
    let manifest_bytes = fs::read(&args.manifest)?;
    let signed_manifest = SignedResourceTrust::decode(&manifest_bytes)
        .map_err(|error| invalid_data("invalid signed resource manifest", error))?;
    let trust = verify_resource_trust_for_spike(&root_pin, &signed_manifest, now_ms()?)
        .map_err(|error| invalid_data("resource trust verification failed", error))?;

    let seed_bytes = fs::read(&args.witness_seed)?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Witness seed must be exactly 32 bytes"))?;
    let signer = SigningKey::from_bytes(&seed);

    // Initialization is explicit and create_new-only. Existing databases are
    // never replaced by startup, even when their contents are corrupt.
    let log = if args.initialize {
        WitnessLog::create(&args.database, trust)
    } else {
        WitnessLog::open(&args.database, trust)
    }
    .map_err(|error| invalid_data("Witness database open failed", error))?;

    let service = WitnessRpcService::new(trust, signer, log)
        .map_err(|error| invalid_data("Witness service configuration failed", error))?;
    let certificate = fs::read(&args.tls_certificate)?;
    let private_key = fs::read(&args.tls_private_key)?;
    let server = WitnessRpcServer::new(
        service,
        certificate,
        private_key,
        64,
        Duration::from_secs(5),
    )
    .map_err(|error| invalid_data("Witness TLS configuration failed", error))?;

    let listener = TcpListener::bind(&args.bind)?;
    let address = listener.local_addr()?;
    println!("Loom Witness RPC listening on {address}");
    println!("TLS server identity is pinned to the Root-authorized Witness Ed25519 key.");
    println!("Append operations require Owner signatures; all reads require fresh challenges.");
    println!("This process does not provide hardware-backed anti-rollback or production ServiceOpen.");

    let shutdown = AtomicBool::new(false);
    server
        .serve(listener, &shutdown)
        .map_err(|error| invalid_data("Witness RPC server stopped", error))
}

fn main() -> Result<(), io::Error> {
    match parse_args()? {
        Some(args) => run(args),
        None => Ok(()),
    }
}
