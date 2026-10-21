//! Explicit loopback-only L-002 lab. All enrolled keys are public fixtures.
#[path = "support/l002_fixture.rs"]
mod fixture;
use fixture::*;
use loom_core::lan_read::*;
use loom_store::witness_append::*;
use loom_transport::secure_channel::*;
use std::{
    fs::File,
    io::{self, Write},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> LabResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).ok_or("mode required")?.as_str();
    let directory = std::path::Path::new(args.get(2).ok_or("directory required")?);
    if mode == "init" {
        Fixture::enroll(directory)?;
        println!("{{\"enrolled\":true,\"fixture_keys\":true}}");
        return Ok(());
    }
    let f = Fixture::load(directory)?;
    let a = f.peer("a");
    let b = f.peer("b");
    match mode {
        "grant" | "revoke" => {
            let signed = f.commit_all(&a, mode == "grant");
            println!(
                "{{\"sequence\":{},\"allow\":{}}}",
                signed.request.expected_generation + 1,
                mode == "grant"
            );
        }
        "prepare" => {
            let history = f
                .log("policy")
                .history()
                .map_err(|e| format!("history {e:?}"))?;
            let signed = f.signed(&history, &a, args.get(3).is_none_or(|a| a == "grant"));
            std::fs::write(directory.join("pending.append"), signed.encode())?;
            println!(
                "{{\"prepared_sequence\":{}}}",
                signed.request.expected_generation + 1
            );
        }
        "append" => {
            let name = args.get(3).ok_or("log name required")?;
            if !["policy", "witness-a", "witness-b"].contains(&name.as_str()) {
                return Err("invalid log".into());
            }
            let cut = args.get(4).map(String::as_str).unwrap_or("");
            let signed = SignedAppend::decode(&std::fs::read(directory.join("pending.append"))?)
                .map_err(|e| format!("decode {e:?}"))?;
            let history = f
                .log(name)
                .append_lab(signed, now(), |point| {
                    if point == cut {
                        println!("{{\"cut\":\"{point}\"}}");
                        io::stdout().flush().unwrap();
                        let mut line = String::new();
                        io::stdin().read_line(&mut line).unwrap();
                    }
                })
                .map_err(|e| format!("append {e:?}"))?;
            println!("{{\"sequence\":{}}}", history.high_water().sequence);
        }
        "status" => {
            for name in ["policy", "witness-a", "witness-b"] {
                let history = f
                    .log(name)
                    .history()
                    .map_err(|e| format!("history {e:?}"))?;
                println!(
                    "{{\"log\":\"{name}\",\"sequence\":{},\"allowed\":{}}}",
                    history.high_water().sequence,
                    history.permits(
                        a.credential.peer(),
                        a.credential.key_epoch(),
                        a.credential.member_epoch(),
                        now()
                    )
                );
            }
        }
        "serve" => {
            let service = LanReadCandidate::from_owner_file(
                f.trust,
                File::open(directory.join("approved.txt"))?,
                f.log("policy"),
            )
            .map_err(|e| format!("enroll file {e:?}"))?;
            // A lab binary must never accidentally expose public fixture keys
            // on a LAN/public interface. Separate processes use real TCP/TLS.
            let address: std::net::SocketAddr = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("127.0.0.1:0")
                .parse()?;
            if !address.ip().is_loopback()
                && std::env::var("LOOM_L002_ISOLATED_LAB").as_deref() != Ok("1")
            {
                return Err(
                    "nonloopback fixture listener requires explicitly isolated laboratory".into(),
                );
            }
            let listener = TcpListener::bind(address).await?;
            println!(
                "{{\"listen\":\"{}\",\"snapshot\":\"{}\"}}",
                listener.local_addr()?,
                hex(&service.snapshot_digest())
            );
            io::stdout().flush()?;
            let (tcp, _) = timeout(Duration::from_secs(15), listener.accept()).await??;
            let mut channel = timeout(
                Duration::from_secs(10),
                accept(tcp, b.identity(), a.context(), &a.verifier),
            )
            .await?
            .map_err(|e| format!("TLS {e:?}"))?;
            let mut session = None;
            // Bounded one-client pull protocol, no remotely supplied paths,
            // grants, offsets or policy mutations. This is NOT frozen wire.
            for _ in 0..1024 {
                let op =
                    match timeout(Duration::from_secs(10), channel.stream_mut().read_u8()).await? {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                let response = match op {
                    1 => {
                        let mut id = [0; 16];
                        channel.stream_mut().read_exact(&mut id).await?;
                        match service.open_read(
                            &channel,
                            &a.credential,
                            &a.verifier,
                            loom_types::ResourceId::from_bytes(id),
                            |c| f.replies(c),
                        ) {
                            Ok(s) => {
                                session = Some(s);
                                Ok(Vec::new())
                            }
                            Err(e) => Err(e),
                        }
                    }
                    2 => {
                        let size = channel.stream_mut().read_u16().await? as usize;
                        match session.as_mut() {
                            Some(s) => service.read_chunk(
                                s,
                                &channel,
                                &a.credential,
                                &a.verifier,
                                size,
                                |c| f.replies(c),
                            ),
                            None => Err(ReadError::Denied),
                        }
                    }
                    _ => Err(ReadError::InvalidInput),
                };
                match response {
                    Ok(bytes) => {
                        channel.stream_mut().write_u8(0).await?;
                        channel.stream_mut().write_u16(bytes.len() as u16).await?;
                        channel.stream_mut().write_all(&bytes).await?;
                    }
                    Err(e) => {
                        println!("{{\"refusal\":\"{e:?}\"}}");
                        io::stdout().flush()?;
                        channel.stream_mut().write_u8(1).await?;
                        channel.stream_mut().write_u16(0).await?;
                    }
                }
            }
        }
        "client" => {
            let address: std::net::SocketAddr = args.get(3).ok_or("address required")?.parse()?;
            if !address.ip().is_loopback()
                && std::env::var("LOOM_L002_ISOLATED_LAB").as_deref() != Ok("1")
            {
                return Err("lab supports loopback only".into());
            }
            let mut channel = timeout(
                Duration::from_secs(10),
                connect(
                    TcpStream::connect(address).await?,
                    a.identity(),
                    b.context(),
                    &b.verifier,
                ),
            )
            .await?
            .map_err(|e| format!("TLS {e:?}"))?;
            let mut line = String::new();
            loop {
                line.clear();
                if io::stdin().read_line(&mut line)? == 0 {
                    break;
                }
                let words: Vec<_> = line.split_whitespace().collect();
                match words.as_slice() {
                    ["open"] => {
                        channel.stream_mut().write_u8(1).await?;
                        channel
                            .stream_mut()
                            .write_all(resource().as_bytes())
                            .await?;
                    }
                    ["wrong-resource"] => {
                        channel.stream_mut().write_u8(1).await?;
                        channel.stream_mut().write_all(&[0; 16]).await?;
                    }
                    ["write"] => {
                        channel.stream_mut().write_u8(3).await?;
                    }
                    ["read", size] => {
                        channel.stream_mut().write_u8(2).await?;
                        channel.stream_mut().write_u16(size.parse()?).await?;
                    }
                    _ => return Err("invalid client command".into()),
                }
                let status =
                    timeout(Duration::from_secs(10), channel.stream_mut().read_u8()).await??;
                let len = channel.stream_mut().read_u16().await? as usize;
                if len > MAX_CHUNK_BYTES {
                    return Err("oversize server reply".into());
                }
                let mut bytes = vec![0; len];
                channel.stream_mut().read_exact(&mut bytes).await?;
                println!(
                    "{{\"ok\":{},\"bytes_hex\":\"{}\"}}",
                    status == 0,
                    hex(&bytes)
                );
                io::stdout().flush()?;
            }
            channel.stream_mut().shutdown().await?;
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
