//! `pinned-shamir` — CLI for Shamir secret sharing with optional pinned shares.
//!
//! Build:  cargo build --example pinned-shamir --all-features --release
//! Usage:
//!   pinned-shamir split <threshold> <limit> --text "secret" | --hex <hex>
//!   pinned-shamir combine [--shares-file <f>]               # else read stdin
//!   pinned-shamir resplit <threshold> <limit>
//!                         --text "new" | --hex <hex>
//!                         (--pin <id:val> | --pin-file <f>)...
//!
//! Share line format (one per line, used by all subcommands):
//!   <id_hex64>:<value_hex64>
//! `id_hex64` and `value_hex64` are 64-char (32-byte) lowercase hex
//! big-endian p256 scalars.

use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;

use elliptic_curve::PrimeField;
use p256::Scalar;
use rand_core::OsRng;
use vsss_rs::{DefaultShare, IdentifierPrimeField, ReadableShareSet, shamir};

type ShareT = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let res = run(&argv);
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: &[String]) -> Result<(), String> {
    let cmd = argv.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "split" => cmd_split(&argv[2..]),
        "combine" => cmd_combine(&argv[2..]),
        "resplit" => cmd_resplit(&argv[2..]),
        "help" | "-h" | "--help" | "" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}` (try `help`)")),
    }
}

fn print_help() {
    println!(
        "vsss-cli — Shamir secret sharing over p256\n\n\
        Subcommands:\n\
        \x20 split   <threshold> <limit> --text <s>|--hex <h>\n\
        \x20 combine [--shares-file <path>]\n\
        \x20 resplit <threshold> <limit> --text <s>|--hex <h>\n\
        \x20         (--pin <id_hex>:<val_hex> | --pin-file <path>)...\n\n\
        Share line format: <id_hex64>:<value_hex64> (one per line)."
    );
}

// ---------- shared parsing ----------

fn pop_flag(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((i, a)) = iter.next() {
        if a == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn collect_flag(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.iter().enumerate();
    while let Some((i, a)) = iter.next() {
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}

fn parse_secret(args: &[String]) -> Result<Scalar, String> {
    if let Some(text) = pop_flag(args, "--text") {
        let bytes = text.as_bytes();
        if bytes.len() > 32 {
            return Err("--text must be at most 32 bytes".into());
        }
        let mut buf = [0u8; 32];
        buf[32 - bytes.len()..].copy_from_slice(bytes);
        scalar_from_bytes(&buf)
    } else if let Some(hex) = pop_flag(args, "--hex") {
        let bytes = decode_hex32(&hex)?;
        scalar_from_bytes(&bytes)
    } else {
        Err("missing --text or --hex".into())
    }
}

fn scalar_from_bytes(b: &[u8; 32]) -> Result<Scalar, String> {
    Option::from(Scalar::from_repr((*b).into()))
        .ok_or_else(|| "secret bytes do not encode a valid p256 scalar".into())
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("bad hex char `{}`", c as char)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(nibble_hex(b >> 4));
        out.push(nibble_hex(b & 0xf));
    }
    out
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

fn share_to_line(s: &ShareT) -> String {
    format!(
        "{}:{}",
        encode_hex(s.identifier.0.to_repr().as_ref()),
        encode_hex(s.value.0.to_repr().as_ref()),
    )
}

fn parse_share_line(line: &str) -> Result<ShareT, String> {
    let line = line.trim();
    let (id_s, val_s) = line
        .split_once(':')
        .ok_or_else(|| format!("bad share line: `{line}` (expected id:value)"))?;
    let id_bytes = decode_hex32(id_s)?;
    let val_bytes = decode_hex32(val_s)?;
    let id = scalar_from_bytes(&id_bytes)?;
    let val = scalar_from_bytes(&val_bytes)?;
    Ok(DefaultShare {
        identifier: IdentifierPrimeField(id),
        value: IdentifierPrimeField(val),
    })
}

fn parse_t_n(args: &[String]) -> Result<(usize, usize), String> {
    let t = args
        .first()
        .ok_or("missing <threshold>")?
        .parse::<usize>()
        .map_err(|e| format!("threshold parse: {e}"))?;
    let n = args
        .get(1)
        .ok_or("missing <limit>")?
        .parse::<usize>()
        .map_err(|e| format!("limit parse: {e}"))?;
    Ok((t, n))
}

// ---------- subcommands ----------

fn cmd_split(args: &[String]) -> Result<(), String> {
    let (t, n) = parse_t_n(args)?;
    let secret = parse_secret(args)?;
    let wrapped = IdentifierPrimeField(secret);
    let shares = shamir::split_secret::<ShareT>(t, n, &wrapped, &mut OsRng)
        .map_err(|e| format!("split: {e:?}"))?;
    let mut out = io::stdout().lock();
    for s in &shares {
        writeln!(out, "{}", share_to_line(s)).unwrap();
    }
    Ok(())
}

fn cmd_combine(args: &[String]) -> Result<(), String> {
    let lines: Vec<String> = if let Some(path) = pop_flag(args, "--shares-file") {
        read_lines_file(&path)?
    } else {
        read_lines_stdin()?
    };
    let shares: Vec<ShareT> = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse_share_line(l))
        .collect::<Result<_, _>>()?;
    if shares.is_empty() {
        return Err("no shares supplied".into());
    }
    let secret = shares
        .combine()
        .map_err(|e| format!("combine: {e:?}"))?;
    let bytes = secret.0.to_repr();
    let bytes_ref = bytes.as_ref();
    println!("hex:  {}", encode_hex(bytes_ref));
    if let Some(text) = try_text(bytes_ref) {
        println!("text: {text}");
    }
    Ok(())
}

fn cmd_resplit(args: &[String]) -> Result<(), String> {
    let (t, n) = parse_t_n(args)?;
    let secret = parse_secret(args)?;
    let wrapped = IdentifierPrimeField(secret);

    let mut pins: Vec<ShareT> = Vec::new();
    for raw in collect_flag(args, "--pin") {
        pins.push(parse_share_line(&raw)?);
    }
    for path in collect_flag(args, "--pin-file") {
        for line in read_lines_file(&path)? {
            if line.trim().is_empty() {
                continue;
            }
            pins.push(parse_share_line(&line)?);
        }
    }
    if pins.is_empty() {
        return Err("no pins supplied (use --pin or --pin-file)".into());
    }

    let shares = shamir::split_secret_with_fixed_shares::<ShareT>(
        t, n, &wrapped, &pins, &mut OsRng,
    )
    .map_err(|e| format!("resplit: {e:?}"))?;
    let mut out = io::stdout().lock();
    for s in &shares {
        writeln!(out, "{}", share_to_line(s)).unwrap();
    }
    Ok(())
}

// ---------- io helpers ----------

fn read_lines_stdin() -> Result<Vec<String>, String> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(buf.lines().map(|s| s.to_string()).collect())
}

fn read_lines_file(path: &str) -> Result<Vec<String>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut out = Vec::new();
    for line in io::BufReader::new(f).lines() {
        out.push(line.map_err(|e| format!("read {path}: {e}"))?);
    }
    Ok(out)
}

/// Try to interpret big-endian zero-padded bytes as UTF-8 by stripping
/// leading zero bytes. Returns None if the result is not valid UTF-8.
fn try_text(bytes: &[u8]) -> Option<String> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];
    if trimmed.is_empty() {
        return Some(String::new());
    }
    core::str::from_utf8(trimmed).ok().map(|s| s.to_string())
}
