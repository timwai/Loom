use loom_core::PeerCore;

fn main() {
    let core = PeerCore::new();
    println!(
        "Loom L-000 bootstrap | state={:?} | network_enabled={}",
        core.state(),
        core.network_listening_enabled()
    );
    println!("Not ready for production. No sockets, proxy, relay, or helper are started.");
}
