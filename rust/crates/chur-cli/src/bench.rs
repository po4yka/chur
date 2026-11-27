//! Benchmarks for the two Phase 0 measurements.
//!
//! `ROADMAP.md` Phase 0 asks for candidate chunk sizes and Argon2id profiles to
//! be benchmarked. `docs/assurance/PERFORMANCE_BUDGETS.md` §1 sets the
//! measurement principles: report p50, p95, and p99, record the sample size,
//! and separate the crypto and storage cost from platform work.
//!
//! These are deliberately not a benchmark framework. The measurement has to
//! run on an Android device and an iOS device through the same code path as
//! the CLI, so it is a subcommand of the binary that already builds for both,
//! and it takes no dependency a framework would add.
//!
//! Nothing here is a gate. §1 of that document requires evidence before a
//! proposal becomes one, and this produces the evidence.

use std::time::{Duration, Instant};

use chur_core::Id;
use chur_core::Result;
use chur_crypto::aead::Nonce;
use chur_crypto::password::{self, Argon2Params};
use chur_crypto::secret::Key;
use chur_format::constants::{MediaClass, StreamKind};
use chur_format::container::{
    CanonicalManifest, ContainerReader, MediaProperties, NONCE_PREFIX_LEN, StreamIdentity,
    encode_container,
};

/// One measured distribution.
struct Samples {
    values: Vec<Duration>,
}

impl Samples {
    fn new(values: Vec<Duration>) -> Self {
        let mut values = values;
        values.sort_unstable();
        Self { values }
    }

    fn quantile(&self, fraction: f64) -> Duration {
        if self.values.is_empty() {
            return Duration::ZERO;
        }
        let last = self.values.len() - 1;
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "an index into a sample vector that never exceeds a few thousand entries"
        )]
        let index = ((last as f64) * fraction).round() as usize;
        self.values[index.min(last)]
    }

    fn total(&self) -> Duration {
        self.values.iter().sum()
    }
}

fn millis(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

fn measure<F>(iterations: usize, mut body: F) -> Result<Samples>
where
    F: FnMut() -> Result<()>,
{
    let mut values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        body()?;
        values.push(started.elapsed());
    }
    Ok(Samples::new(values))
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

fn identity() -> Result<StreamIdentity> {
    Ok(StreamIdentity {
        object_id: Id::new([0x33; 16])?,
        stream_id: Id::new([0x34; 16])?,
        stream_kind: StreamKind::Original,
        stream_revision: 1,
    })
}

/// Benchmarks the chunk-size candidates of `OBJECT_CONTAINER_V1.md` §6.
///
/// It reports three costs per candidate, because they trade against each other:
/// sealing a whole object, verifying it completely, and one random single-byte
/// range read, which is the seek amplification a larger chunk buys.
///
/// # Errors
///
/// Returns an error when a construction fails, which for fixed inputs means the
/// library is broken.
pub fn chunk_sizes(object_bytes: usize, iterations: usize) -> Result<()> {
    let object_key = Key::new([0x77; 32]);
    let plaintext = pattern(object_bytes);

    println!("chunk-size candidates");
    println!("  object plaintext       {object_bytes} bytes");
    println!("  samples per candidate  {iterations}");
    println!();
    println!(
        "{:>10}  {:>7}  {:>10}  {:>10}  {:>10}  {:>10}",
        "chunk", "chunks", "write p50", "verify p50", "seek p50", "seek p95"
    );

    for chunk_size in [65_536u32, 262_144, 1_048_576, 4_194_304, 8_388_608] {
        let manifest = CanonicalManifest::new(
            identity()?,
            None,
            chunk_size,
            [0x35; NONCE_PREFIX_LEN],
            1,
            MediaProperties::new(MediaClass::Opaque, 0, 0, 0)?,
        )?;
        let container = encode_container(
            &object_key,
            manifest.clone(),
            Nonce::new([0x36; 24]),
            &plaintext,
            Nonce::new([0x37; 24]),
            1,
        )?;
        let chunk_count = object_bytes.div_ceil(chunk_size as usize);

        let write = measure(iterations, || {
            encode_container(
                &object_key,
                manifest.clone(),
                Nonce::new([0x36; 24]),
                &plaintext,
                Nonce::new([0x37; 24]),
                1,
            )
            .map(|_| ())
        })?;

        let verify = measure(iterations, || {
            let reader = ContainerReader::open(&container, &object_key, &identity()?)?;
            reader.verify_complete().map(|_| ())
        })?;

        // One byte at a pseudo-random offset. The cost is one whole chunk
        // authenticated for one byte returned, which is the amplification the
        // candidate is chosen against.
        let reader = ContainerReader::open(&container, &object_key, &identity()?)?;
        let mut offset = 0u64;
        let seek = measure(iterations.max(16), || {
            offset = offset
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let at = offset % object_bytes.max(1) as u64;
            reader.read_range(at, 1).map(|_| ())
        })?;

        println!(
            "{:>10}  {:>7}  {:>9.2}m  {:>9.2}m  {:>9.2}m  {:>9.2}m",
            chunk_size,
            chunk_count,
            millis(write.quantile(0.50)),
            millis(verify.quantile(0.50)),
            millis(seek.quantile(0.50)),
            millis(seek.quantile(0.95)),
        );
    }
    println!();
    println!("Times are milliseconds. A larger chunk lowers per-record overhead");
    println!("and raises the cost of a single-byte read, which is the trade the");
    println!("candidates in OBJECT_CONTAINER_V1.md section 6 are choosing between.");
    Ok(())
}

/// Benchmarks Argon2id profiles against the interactive target.
///
/// `PASSWORD_PROFILE.md` §4 fixes the floor at 65536 KiB, 3 iterations, and
/// parallelism 1, and sets an interactive target of roughly 350 to 750 ms per
/// derivation on the floor device. `KEY_SLOTS.md` §8 runs two candidates per
/// unlock attempt, so the whole-attempt cost is twice a single derivation.
///
/// Calibration may raise memory or iterations inside the §18.3 bounds and may
/// never lower any parameter, so a candidate below the floor is not measured.
///
/// # Errors
///
/// Returns an error when a derivation fails, which for a valid profile means
/// the device could not allocate the memory it requires.
pub fn argon2(iterations: usize) -> Result<()> {
    let salt = [0x77u8; 16];
    let password = b"correct horse battery staple";

    println!("Argon2id profiles");
    println!("  samples per profile    {iterations}");
    println!("  interactive target     350 to 750 ms per derivation");
    println!("  attempt cost           two derivations, KEY_SLOTS.md section 8");
    println!();
    println!(
        "{:>10}  {:>5}  {:>5}  {:>11}  {:>11}  {:>11}  {:>13}",
        "memory KiB", "iter", "lanes", "p50", "p95", "p99", "attempt p50"
    );

    let candidates = [
        (65_536u32, 3u32, 1u32),
        (65_536, 4, 1),
        (65_536, 6, 1),
        (131_072, 3, 1),
        (131_072, 4, 1),
        (262_144, 3, 1),
        (524_288, 3, 1),
        (65_536, 3, 2),
        (65_536, 3, 4),
    ];

    for (memory_kib, passes, lanes) in candidates {
        let params = Argon2Params::validated(memory_kib, passes, lanes)?;
        let samples = measure(iterations, || {
            password::derive_kek(password, &salt, params).map(|_| ())
        })?;
        let p50 = samples.quantile(0.50);
        println!(
            "{:>10}  {:>5}  {:>5}  {:>10.1}m  {:>10.1}m  {:>10.1}m  {:>12.1}m",
            memory_kib,
            passes,
            lanes,
            millis(p50),
            millis(samples.quantile(0.95)),
            millis(samples.quantile(0.99)),
            millis(p50 * 2),
        );
        let _ = samples.total();
    }
    println!();
    println!("Times are milliseconds on this host, which is not a device from");
    println!("ADR-0017. PERFORMANCE_BUDGETS.md section 6 approves a candidate");
    println!("against the floor device, so these numbers rank candidates and");
    println!("approve none. A candidate that fits only a fast host is rejected.");
    Ok(())
}

/// Benchmarks the random-seek budget of `PERFORMANCE_BUDGETS.md` §2.
///
/// The row is "random video seek crypto/data-source overhead, p95 <150 ms
/// excluding codec/network", so this measures what a player's data source costs
/// and nothing a codec does: opening a reader on a committed container and
/// pulling one range at a pseudo-random offset, through the same
/// `chur_media::reader` a Media3 `DataSource` and an
/// `AVAssetResourceLoaderDelegate` call.
///
/// It differs from the seek column of [`chunk_sizes`] in the two ways that
/// matter for the budget. The container is written at the 1 MiB video chunk of
/// `OBJECT_CONTAINER_V1.md` §6 rather than at every candidate, and the range is
/// a player-sized read rather than one byte, so the number includes the copy a
/// player actually asks for.
///
/// # Errors
///
/// Returns an error when a construction fails, which for fixed inputs means the
/// library is broken.
pub fn random_seek(object_bytes: usize, iterations: usize, range_bytes: usize) -> Result<()> {
    let object_key = Key::new([0x77; 32]);
    let plaintext = pattern(object_bytes);
    let chunk_size = 1_048_576u32;
    let manifest = CanonicalManifest::new(
        identity()?,
        None,
        chunk_size,
        [0x35; NONCE_PREFIX_LEN],
        1,
        MediaProperties::new(MediaClass::Video, 1_920, 1_080, 600_000)?,
    )?;
    let container = encode_container(
        &object_key,
        manifest,
        Nonce::new([0x36; 24]),
        &plaintext,
        Nonce::new([0x37; 24]),
        1,
    )?;

    println!("random seek");
    println!("  object plaintext  {object_bytes} bytes");
    println!("  chunk size        {chunk_size} bytes");
    println!("  range per seek    {range_bytes} bytes");
    println!("  samples           {iterations}");
    println!();

    // One reader held across the seeks, which is what a player does: it opens
    // a data source once and seeks inside it many times.
    let reader = ContainerReader::open(&container, &object_key, &identity()?)?;
    let span = (object_bytes - range_bytes) as u64;
    let mut offset: u64 = 1;
    let warm = measure(iterations, || {
        offset = offset
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        reader
            .read_range(offset % span, range_bytes as u64)
            .map(|_| ())
    })?;

    // A cold seek reopens the reader, which is what happens after a lock and
    // after a process death: the manifest is authenticated again first.
    let cold = measure(iterations, || {
        offset = offset
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let reader = ContainerReader::open(&container, &object_key, &identity()?)?;
        reader
            .read_range(offset % span, range_bytes as u64)
            .map(|_| ())
    })?;

    println!("{:>12}  {:>9}  {:>9}  {:>9}", "seek", "p50", "p95", "p99");
    for (name, samples) in [("warm", &warm), ("cold", &cold)] {
        println!(
            "{:>12}  {:>8.3}m  {:>8.3}m  {:>8.3}m",
            name,
            millis(samples.quantile(0.50)),
            millis(samples.quantile(0.95)),
            millis(samples.quantile(0.99))
        );
    }
    println!();
    println!("§2's row is p95 under 150 ms excluding codec and network. This host is");
    println!("not a device from ADR-0017, so the numbers rank the work and approve no");
    println!("budget; §1 requires a release-like build on the frozen device set.");
    Ok(())
}

/// Benchmarks the lock-invalidation budget of `PERFORMANCE_BUDGETS.md` §2.
///
/// The row is "panic/explicit lock native invalidation, p95 <100 ms; UI cover
/// immediate". This measures the native half: `Session::lock`, which closes the
/// catalog and clears the plaintext scratch directory of
/// `PLAINTEXT_LIFECYCLE.md` §5.
///
/// It does not measure the whole of §8 there. Step 6, zeroizing the root, runs
/// on `Drop` rather than inside `lock`, and the UI cover is a host concern that
/// §2 already separates. What is measured is the part a lock latency budget is
/// about: the moment after which no handle can read plaintext.
///
/// # Errors
///
/// Returns an error when a vault cannot be created in the temporary directory.
pub fn lock_invalidation(iterations: usize) -> Result<()> {
    use chur_catalog::paths::VaultRoot;

    let password = b"correct horse battery staple";
    let now = crate::vault::now_ms();

    println!("lock invalidation");
    println!("  samples  {iterations}");
    println!();

    let mut values = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chur-lock-bench-{}",
            chur_crypto::random::id()?.to_hex()
        ));
        let root = VaultRoot::new(path.clone());
        let mut session = chur_catalog::vault::create(&root, password, now)?.activate()?;
        // A scratch entry and an open catalog are what a lock has to clear, so
        // the vault is put in the state an unlocked session is really in.
        let _ = chur_catalog::store::albums(session.catalog_ref()?)?;

        let started = Instant::now();
        session.lock()?;
        values.push(started.elapsed());

        drop(session);
        let _ = std::fs::remove_dir_all(&path);
    }
    let samples = Samples::new(values);

    println!("{:>12}  {:>9}  {:>9}  {:>9}", "lock", "p50", "p95", "p99");
    println!(
        "{:>12}  {:>8.3}m  {:>8.3}m  {:>8.3}m",
        "native",
        millis(samples.quantile(0.50)),
        millis(samples.quantile(0.95)),
        millis(samples.quantile(0.99))
    );
    println!();
    println!("§2's row is p95 under 100 ms. This covers PLAINTEXT_LIFECYCLE.md §8 steps");
    println!("5 and 8: the catalog closes and the scratch directory is cleared. Step 6,");
    println!("zeroizing the root, runs on Drop and is not in the number. The host is not");
    println!("a device from ADR-0017, so this approves no budget.");
    Ok(())
}
