//! Run a read-only TPM2 capability probe on a disposable Linux test host.
//! It NEVER provisions NV indices or enables Loom network access.
use loom_store::linux_tpm2_probe::probe_linux_tpm2;

fn main() {
    match probe_linux_tpm2() {
        Ok(candidate) => {
            println!("Loom Linux TPM2 probe (read-only)");
            println!("TPM resource manager: /dev/tpmrm{}", candidate.device_index);
            println!("TPM family: 0x{:08x}", candidate.family);
            println!("Manufacturer ID: 0x{:08x}", candidate.manufacturer);
            println!("NV page complete: {}", !candidate.nv_list_incomplete);
            println!("NV indices returned: {}", candidate.nv_handles.len());
            for handle in &candidate.nv_handles {
                println!("NV handle: 0x{handle:08x}");
            }
            println!("Hardware verified: {}", candidate.device_certified);
            println!("Safe independent high-water: {}", candidate.anchor_ready);
            println!("ServiceOpen: disabled (candidate capability probe only)");
        }
        Err(error) => {
            eprintln!("Loom Linux TPM2 read-only probe denied: {error:?}");
            eprintln!("No fallback to local files, SQLite, TPM1.2 or untrusted NV state.");
            std::process::exit(2);
        }
    }
}
