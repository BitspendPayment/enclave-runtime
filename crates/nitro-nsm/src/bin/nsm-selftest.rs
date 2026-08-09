//! Prove the Nitro Security Module answers, from inside an enclave.
//!
//! Deliberately tiny and pure Rust: this is what goes into the enclave ramdisk
//! as a statically linked musl binary, where the full runtime's C dependencies
//! and dynamic linking would be a problem for no benefit. It touches no
//! storage and needs no network — the NSM is the only thing under test.
//!
//! Prints `NSM-SELFTEST-OK` on success and `NSM-SELFTEST-FAIL: …` otherwise,
//! sentinels the harness greps for in the console log.

use std::time::Instant;

use nitro_nsm::{Nsm, NsmDevice, DEFAULT_NSM_DEVICE};

fn main() {
    let device = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_NSM_DEVICE.to_string());
    match run(&device) {
        Ok(()) => println!("NSM-SELFTEST-OK"),
        Err(e) => {
            println!("NSM-SELFTEST-FAIL: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run(device: &str) -> anyhow::Result<()> {
    println!("opening {device}");
    let nsm = NsmDevice::open(device)?;
    println!("{}", nsm.describe());

    let mut first = [0u8; 64];
    let started = Instant::now();
    nsm.get_random(&mut first)?;
    let one_read = started.elapsed();

    let mut second = [0u8; 64];
    nsm.get_random(&mut second)?;

    // The failures an emulated or half-wired device actually produces.
    if first.iter().all(|&b| b == 0) {
        anyhow::bail!("GetRandom returned all zeros");
    }
    if first.iter().all(|&b| b == first[0]) {
        anyhow::bail!("GetRandom returned the constant byte {:#04x}", first[0]);
    }
    if first == second {
        anyhow::bail!("two draws were identical; the device is not advancing");
    }

    // Larger than one 256-byte device answer, so the chunk loop is exercised.
    let mut bulk = vec![0u8; 4096];
    let bulk_started = Instant::now();
    nsm.get_random(&mut bulk)?;
    let bulk_read = bulk_started.elapsed();

    let mut histogram = [0u32; 256];
    for &b in &bulk {
        histogram[b as usize] += 1;
    }
    let peak = histogram.iter().copied().max().unwrap_or(0);
    if peak > 80 {
        anyhow::bail!("byte histogram peaks at {peak} of 4096; the device looks stuck");
    }

    println!(
        "sample     {}",
        first[..16].iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("histogram  peak {peak} of 4096 (mean 16)");
    println!(
        "read cost  {:.1} us for 64 bytes, {:.1} us for 4096",
        one_read.as_secs_f64() * 1e6,
        bulk_read.as_secs_f64() * 1e6
    );
    Ok(())
}
