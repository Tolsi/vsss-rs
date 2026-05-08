//! Demo: pinning a Shamir share across re-splits.
//!
//! Splits the phrase "test" into 5 shares (3-of-5 Shamir, "split 1"),
//! then reuses one share from split 1 to construct "split 2" — a brand
//! new 3-of-5 polynomial that nevertheless agrees with split 1 at the
//! pinned identifier.
//!
//! Run with: cargo run --example demo --all-features

use elliptic_curve::PrimeField;
use p256::Scalar;
use rand_core::OsRng;
use vsss_rs::{DefaultShare, IdentifierPrimeField, ReadableShareSet, shamir};

type TestShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

fn main() {
    let mut osrng = OsRng;

    // Encode the phrase "test" as the secret scalar by zero-padding into
    // a 32-byte big-endian repr. Educational only — not collision-safe.
    let mut bytes = [0u8; 32];
    let msg = b"test";
    let start = bytes.len() - msg.len();
    bytes[start..].copy_from_slice(msg);
    let secret = Scalar::from_repr(bytes.into()).expect("valid scalar");
    let wrapped_secret = IdentifierPrimeField(secret);

    println!("=== VSSS Demo: pinning shares across re-splits ===");
    println!("Secret encodes \"test\":   {}", hex32(&bytes));

    // ---- Split 1: standard 3/5 Shamir ----
    println!("\n--- Split 1 (3/5, fresh polynomial) ---");
    let split1 = shamir::split_secret::<TestShare>(3, 5, &wrapped_secret, &mut osrng).unwrap();
    print_shares("S1", &split1);
    let r1 = split1[..3].to_vec().combine().unwrap();
    println!("  combine S1[0..3] -> matches secret? {}", r1.0 == secret);

    // ---- Split 2: pin S1[0] into a new 3/5 polynomial ----
    let pinned = split1[0].clone();
    println!("\n--- Split 2 (3/5, pinning S1[0]) ---");
    let split2 = shamir::split_secret_with_fixed_shares::<TestShare>(
        3,
        5,
        &wrapped_secret,
        core::slice::from_ref(&pinned),
        &mut osrng,
    )
    .unwrap();
    print_shares("S2", &split2);

    println!(
        "  S2[0] == S1[0]?                       {}",
        split2[0] == pinned
    );
    println!(
        "  S2[1] differs from S1[1] (fresh poly)?{}",
        split2[1] != split1[1]
    );
    let r2 = split2[..3].to_vec().combine().unwrap();
    println!("  combine S2[0..3] -> matches secret?   {}", r2.0 == secret);

    // Pinned share interchanges with the matching slot of either split,
    // because both polynomials evaluate to the same value at that x.
    let mixed = vec![pinned.clone(), split2[1].clone(), split2[2].clone()];
    let r_mix = mixed.combine().unwrap();
    println!(
        "\nCross-combine S1[0] + S2[1] + S2[2]    -> matches secret? {}",
        r_mix.0 == secret
    );

    // Mixing non-pinned shares from different splits will NOT recover
    // the secret — those points lie on two different polynomials.
    let bad = vec![split1[1].clone(), split1[2].clone(), split2[3].clone()];
    let r_bad = bad.combine().unwrap();
    println!(
        "Bad-mix    S1[1] + S1[2] + S2[3]       -> matches secret? {} (expected: false)",
        r_bad.0 == secret
    );

    // ---- Split 3: pin t-1 = 2 shares -> polynomial fully determined ----
    println!("\n--- Split 3 (3/5, pinning 2 shares = fully determined) ---");
    let two_pins = vec![split1[0].clone(), split1[1].clone()];
    let split3 = shamir::split_secret_with_fixed_shares::<TestShare>(
        3,
        5,
        &wrapped_secret,
        &two_pins,
        &mut osrng,
    )
    .unwrap();
    print_shares("S3", &split3);
    let identical = split3.iter().zip(split1.iter()).all(|(a, b)| a == b);
    println!("  S3 reproduces S1 entirely? {}", identical);

    // ---- Split 4: DIFFERENT secret, but still pin S1[0] verbatim ----
    // The new polynomial p4 must satisfy:
    //   p4(0)        = secret_b   (new secret)
    //   p4(S1[0].id) = S1[0].val  (carried over from split 1)
    // Mathematically fine — pinning is independent of the secret value.
    let mut bytes_b = [0u8; 32];
    let msg_b = b"other";
    let start_b = bytes_b.len() - msg_b.len();
    bytes_b[start_b..].copy_from_slice(msg_b);
    let secret_b = Scalar::from_repr(bytes_b.into()).expect("valid scalar");
    let wrapped_secret_b = IdentifierPrimeField(secret_b);
    assert_ne!(secret, secret_b);

    println!("\n--- Split 4 (3/5, NEW secret \"other\", pinning S1[0]) ---");
    println!("  secret_b encodes \"other\": {}", hex32(&bytes_b));
    let split4 = shamir::split_secret_with_fixed_shares::<TestShare>(
        3,
        5,
        &wrapped_secret_b,
        core::slice::from_ref(&pinned),
        &mut osrng,
    )
    .unwrap();
    print_shares("S4", &split4);

    println!(
        "  S4[0] == S1[0]?                      {}",
        split4[0] == pinned
    );
    let r4 = split4[..3].to_vec().combine().unwrap();
    println!(
        "  combine S4[0..3] -> matches secret_b? {} (matches old secret? {})",
        r4.0 == secret_b,
        r4.0 == secret
    );

    // Cross-combine across two different secrets:
    // S1[0] is on BOTH polynomials at x=1, so substituting it for S4[0]
    // still recovers secret_b — the pinned point lies on p4 by construction.
    let mix4 = vec![pinned.clone(), split4[1].clone(), split4[2].clone()];
    let r_mix4 = mix4.combine().unwrap();
    println!(
        "  cross S1[0] + S4[1] + S4[2] -> secret_b? {} (secret_a? {})",
        r_mix4.0 == secret_b,
        r_mix4.0 == secret
    );

    // ---- Split 5: ANOTHER new secret, pin 2 shares from different splits ----
    // Pins: S1[2] (id=3, lies on p1) and S4[3] (id=4, lies on p4).
    // With threshold=3, two pins + (0, secret_c) fully determine p5.
    let mut bytes_c = [0u8; 32];
    let msg_c = b"third";
    let start_c = bytes_c.len() - msg_c.len();
    bytes_c[start_c..].copy_from_slice(msg_c);
    let secret_c = Scalar::from_repr(bytes_c.into()).expect("valid scalar");
    let wrapped_secret_c = IdentifierPrimeField(secret_c);
    assert_ne!(secret_c, secret);
    assert_ne!(secret_c, secret_b);

    println!("\n--- Split 5 (3/5, NEW secret \"third\", pinning S1[2] + S4[3]) ---");
    println!("  secret_c encodes \"third\": {}", hex32(&bytes_c));
    let cross_pins = vec![split1[2].clone(), split4[3].clone()];
    let split5 = shamir::split_secret_with_fixed_shares::<TestShare>(
        3,
        5,
        &wrapped_secret_c,
        &cross_pins,
        &mut osrng,
    )
    .unwrap();
    print_shares("S5", &split5);

    println!(
        "  S5[0] == S1[2]? {}  S5[1] == S4[3]? {}",
        split5[0] == split1[2],
        split5[1] == split4[3]
    );
    let r5 = split5[..3].to_vec().combine().unwrap();
    println!(
        "  combine S5[0..3] -> secret_c? {} (secret_a? {}, secret_b? {})",
        r5.0 == secret_c,
        r5.0 == secret,
        r5.0 == secret_b
    );

    // Cross-combine: pinned origin shares + one fresh from split 5.
    let mix5 = vec![split1[2].clone(), split4[3].clone(), split5[2].clone()];
    let r_mix5 = mix5.combine().unwrap();
    println!(
        "  cross S1[2] + S4[3] + S5[2] -> secret_c? {}",
        r_mix5.0 == secret_c
    );

    // ---- Split 6: NEW secret, pin 3 shares from 3 different polynomials ----
    // 3 pins require threshold > 3. Use 4/5 Shamir; with k = 3 = t - 1 the
    // polynomial p6 of degree 3 is uniquely determined by
    //   (0, secret_d), (1, S1[0].val), (2, S2[1].val), (3, S4[2].val).
    let mut bytes_d = [0u8; 32];
    let msg_d = b"fourth";
    let start_d = bytes_d.len() - msg_d.len();
    bytes_d[start_d..].copy_from_slice(msg_d);
    let secret_d = Scalar::from_repr(bytes_d.into()).expect("valid scalar");
    let wrapped_secret_d = IdentifierPrimeField(secret_d);
    assert_ne!(secret_d, secret);
    assert_ne!(secret_d, secret_b);
    assert_ne!(secret_d, secret_c);

    println!("\n--- Split 6 (4/5, NEW secret \"fourth\", pinning S1[0]+S2[1]+S4[2]) ---");
    println!("  secret_d encodes \"fourth\": {}", hex32(&bytes_d));
    let three_pins = vec![split1[0].clone(), split2[1].clone(), split4[2].clone()];
    let split6 = shamir::split_secret_with_fixed_shares::<TestShare>(
        4,
        5,
        &wrapped_secret_d,
        &three_pins,
        &mut osrng,
    )
    .unwrap();
    print_shares("S6", &split6);

    println!(
        "  S6[0]==S1[0]? {}  S6[1]==S2[1]? {}  S6[2]==S4[2]? {}",
        split6[0] == split1[0],
        split6[1] == split2[1],
        split6[2] == split4[2]
    );
    let r6 = split6[..4].to_vec().combine().unwrap();
    println!(
        "  combine S6[0..4] -> secret_d? {} (secret_a? {}, secret_b? {}, secret_c? {})",
        r6.0 == secret_d,
        r6.0 == secret,
        r6.0 == secret_b,
        r6.0 == secret_c
    );

    // Cross-combine using only the original (pinned) shares plus one fresh.
    let mix6 = vec![
        split1[0].clone(),
        split2[1].clone(),
        split4[2].clone(),
        split6[3].clone(),
    ];
    let r_mix6 = mix6.combine().unwrap();
    println!(
        "  cross S1[0]+S2[1]+S4[2]+S6[3] -> secret_d? {}",
        r_mix6.0 == secret_d
    );

    println!("\nNote: pinning shares across splits intentionally leaks");
    println!("structure of the new polynomial to anyone holding the pinned");
    println!("share. Only safe in proactive-secret-sharing protocols and");
    println!("educational settings.");
}

fn print_shares(label: &str, shares: &[TestShare]) {
    for (i, s) in shares.iter().enumerate() {
        println!(
            "  {}[{}]: id={} val={}",
            label,
            i,
            hex32(s.identifier.0.to_repr().as_ref()),
            hex32(s.value.0.to_repr().as_ref()),
        );
    }
}

fn hex32(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push_str(&format!("{:02x}", x));
    }
    out
}
