//! BLINCS benchmark using bench-hashes' `clocks` crate: wall time and core cycles together,
//! with background-load detection (`clocks::load`). All summaries are integer arithmetic
//! over the run's totals (`sum(wall_ns) / sum(calls)`).

use blincs::{Randomness, SEED_LEN, SigningKey, VerifyingKey};
use std::hint::black_box;
use std::io::Cursor;

struct Summary {
    calls: u64,
    wall_ns: u64,
    cycles: u64,
    instructions: u64,
    have_counts: bool,
    mhz: u64,
    e_pct: u64,
}

fn summarize(batches: &[clocks::Batch]) -> Summary {
    let mut calls = 0u64;
    let mut wall_ns = 0u64;
    let mut cycles = 0u64;
    let mut instructions = 0u64;
    let mut total_counts = clocks::Counts::default();
    let mut have_counts = false;
    for b in batches {
        calls += b.calls;
        wall_ns += b.wall_ns;
        if let Some(c) = b.counts {
            have_counts = true;
            cycles += c.p.cycles + c.e.cycles;
            instructions += c.p.instructions + c.e.instructions;
            total_counts = total_counts.plus(c);
        }
    }
    let mhz = if have_counts { total_counts.mhz() } else { 0 };
    let e_pct = if have_counts { total_counts.e_percent() } else { 0 };
    Summary { calls, wall_ns, cycles, instructions, have_counts, mhz, e_pct }
}

fn format_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        let hundredths = (ns + 5_000) / 10_000;
        format!("{}.{:02} ms", hundredths / 100, hundredths % 100)
    } else if ns >= 1_000 {
        let tenths = (ns + 50) / 100;
        format!("{}.{} us", tenths / 10, tenths % 10)
    } else {
        format!("{ns} ns")
    }
}

fn report(label: &str, batches: &[clocks::Batch], bytes_per_call: u64) {
    let s = summarize(batches);
    let ns_per_call = (s.wall_ns + s.calls / 2) / s.calls;
    let cyc_str = if s.have_counts {
        let cyc_per_call = (s.cycles + s.calls / 2) / s.calls;
        let ins_per_call = (s.instructions + s.calls / 2) / s.calls;
        let ipc_hundredths = if s.cycles > 0 { (s.instructions * 100 + s.cycles / 2) / s.cycles } else { 0 };
        format!(
            "{:>11} cyc  {:>11} ins  {}.{:02} IPC  {:>4} MHz ({}% E)",
            cyc_per_call,
            ins_per_call,
            ipc_hundredths / 100,
            ipc_hundredths % 100,
            s.mhz,
            s.e_pct
        )
    } else {
        "no cycle counts".to_owned()
    };
    let rate_str = if bytes_per_call > 0 {
        // MB/s = bytes * 1000 / ns  (decimal MB/s, integer)
        let mb_s = (bytes_per_call as u128 * s.calls as u128 * 1000 + (s.wall_ns as u128 / 2)) / s.wall_ns as u128;
        format!("  {:>5} MB/s", mb_s)
    } else {
        String::new()
    };
    println!("{label:<28} {:>10}  (n={:<5})  {cyc_str}{rate_str}", format_ns(ns_per_call), s.calls);
}

fn main() {
    println!("wall clock: {}", clocks::WALL_CLOCK);
    println!("counter overhead: {}", clocks::read_overhead());

    let dir = std::env::temp_dir().join(format!("blincs-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.bin");
    Randomness::create(&state).unwrap();
    let rng = Randomness::initialize(&state).unwrap();

    let seed = [0x42u8; SEED_LEN];
    let sk = SigningKey::from_seed(&seed);
    let vk = VerifyingKey::from_bytes(sk.verifying_key().as_bytes());

    // Warm up the CPU / SME2 unit and thread-local workspaces.
    for _ in 0..8 {
        let s = sk.sign(&rng, b"warmup");
        assert!(vk.verify(b"warmup", &s));
    }

    let b = clocks::measure(10, 100_000_000, || {
        black_box(SigningKey::from_seed(black_box(&seed)));
    });
    report("from_seed (keygen/load)", &b, 0);

    for &(label, len) in &[
        ("64 B", 64usize),
        ("1 KiB", 1024),
        ("64 KiB", 65536),
        ("256 KiB", 262144),
        ("1 MiB", 1024 * 1024),
        ("16 MiB", 16 * 1024 * 1024),
        ("100 MiB", 100 * 1024 * 1024),
    ] {
        let msg: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) & 0xff) as u8).collect();
        let sig = sk.sign(&rng, &msg);
        assert!(vk.verify(&msg, &sig));

        let sign_batches = clocks::measure(12, 150_000_000, || {
            black_box(sk.sign(&rng, black_box(&msg)));
        });
        report(&format!("sign slice {label}"), &sign_batches, if len >= 65536 { len as u64 } else { 0 });

        let ver_batches = clocks::measure(12, 100_000_000, || {
            assert!(black_box(vk.verify(black_box(&msg), black_box(&sig))));
        });
        report(&format!("verify slice {label}"), &ver_batches, if len >= 65536 { len as u64 } else { 0 });

        if len == 64 || len == 262144 || len == 1024 * 1024 || len == 100 * 1024 * 1024 {
            let sr = clocks::measure(10, 150_000_000, || {
                black_box(sk.sign_reader(&rng, Cursor::new(black_box(&msg))).unwrap());
            });
            report(&format!("sign_reader {label}"), &sr, if len >= 65536 { len as u64 } else { 0 });

            let vr = clocks::measure(10, 100_000_000, || {
                assert!(black_box(vk.verify_reader(Cursor::new(black_box(&msg)), black_box(&sig)).unwrap()));
            });
            report(&format!("verify_reader {label}"), &vr, if len >= 65536 { len as u64 } else { 0 });
        }
    }

    let init_batches = clocks::measure(10, 50_000_000, || {
        black_box(Randomness::initialize(&state).unwrap());
    });
    report("Randomness::initialize", &init_batches, 0);

    let _ = std::fs::remove_dir_all(&dir);
}
