/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Secret splitting for Shamir Secret Sharing Scheme
//! and combine methods for field and group elements
use super::*;
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::{Array, ArraySize};
use rand_core::{CryptoRng, RngCore};

/// A Polynomial that can create secret shares
pub trait Shamir<S>
where
    S: Share,
{
    /// The polynomial for the coefficients
    type InnerPolynomial: Polynomial<S>;
    /// The set of secret shares
    type ShareSet: WriteableShareSet<S>;

    /// Create shares from a secret.
    fn split_secret(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl RngCore + CryptoRng,
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let generator = ParticipantIdGeneratorType::<S::Identifier>::default();
        Self::split_secret_with_participant_generator(threshold, limit, secret, rng, &[generator])
    }

    /// Create shares from a secret and a participant number generator.
    /// `F` is the prime field
    fn split_secret_with_participant_generator(
        threshold: usize,
        limit: usize,
        secret: &S::Value,
        rng: impl RngCore + CryptoRng,
        participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
    ) -> VsssResult<Self::ShareSet> {
        check_params(threshold, limit)?;
        let mut polynomial = Self::InnerPolynomial::create(threshold);
        polynomial.fill(secret, rng, threshold)?;
        let ss = create_shares_with_participant_generator(
            &polynomial,
            threshold,
            limit,
            participant_generators,
        )?;
        Ok(ss)
    }
}

pub(crate) fn create_shares_with_participant_generator<P, S, SS>(
    polynomial: &P,
    threshold: usize,
    limit: usize,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<SS>
where
    P: Polynomial<S>,
    S: Share,
    SS: WriteableShareSet<S>,
{
    // Generate the shares of (x, y) coordinates
    // x coordinates are in the range from [1, N+1). 0 is reserved for the secret
    let mut shares = SS::create(limit);
    let indexer = shares.as_mut();

    let participant_id_collection = ParticipantIdGeneratorCollection::from(participant_generators);

    let mut participant_id_iter = participant_id_collection.iter();

    for s in indexer.iter_mut().take(limit) {
        let id = participant_id_iter
            .next()
            .ok_or(Error::NotEnoughShareIdentifiers)?;
        let value = polynomial.evaluate(&id, threshold);
        let share = S::with_identifier_and_value(id, value);
        *s = share;
    }
    Ok(shares)
}

pub(crate) fn check_params(threshold: usize, limit: usize) -> VsssResult<()> {
    if limit < threshold {
        return Err(Error::SharingLimitLessThanThreshold);
    }
    if threshold < 2 {
        return Err(Error::SharingMinThreshold);
    }
    Ok(())
}

impl<S: Share, const L: usize> Shamir<S> for [S; L] {
    type InnerPolynomial = [S; L];
    type ShareSet = [S; L];
}

impl<S: Share, L: ArrayLength> Shamir<S> for GenericArray<S, L> {
    type InnerPolynomial = GenericArray<S, L>;
    type ShareSet = GenericArray<S, L>;
}

impl<S: Share, L: ArraySize> Shamir<S> for Array<S, L> {
    type InnerPolynomial = Array<S, L>;
    type ShareSet = Array<S, L>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share> Shamir<S> for Vec<S> {
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret.
pub fn split_secret<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl RngCore + CryptoRng,
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret(threshold, limit, secret, rng)
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret and a participant number generator.
pub fn split_secret_with_participant_generator<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    rng: impl RngCore + CryptoRng,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<Vec<S>> {
    StdVsssShamir::split_secret_with_participant_generator(
        threshold,
        limit,
        secret,
        rng,
        participant_generators,
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
struct StdVsssShamir<S: Share> {
    _marker: core::marker::PhantomData<S>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<S: Share> Shamir<S> for StdVsssShamir<S> {
    type InnerPolynomial = Vec<S>;
    type ShareSet = Vec<S>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Create shares from a secret while pinning specific `(identifier, value)`
/// pairs from a previous splitting.
///
/// This forces the new polynomial to evaluate to the supplied values at the
/// supplied identifiers (and to the secret at zero). The polynomial is
/// otherwise random within those constraints.
///
/// # WARNING — educational / proactive use only
/// Standard Shamir produces a fresh, independent polynomial on every split.
/// Pinning shares from a previous split into a new one intentionally reuses
/// `(id, value)` points across two distinct polynomials. Anyone holding a
/// pinned share now learns one extra equation about the new polynomial,
/// reducing its entropy. With `threshold - 1` pins, the polynomial is
/// fully determined and the new "split" is deterministic. Only use this
/// when you understand and accept the cost (proactive secret sharing,
/// deterministic re-derivation, demos).
///
/// `fixed_shares` are emitted verbatim at the head of the returned vector.
/// The remaining `limit - fixed_shares.len()` shares are produced by
/// evaluating the constructed polynomial at fresh identifiers from the
/// default participant generator (sequential, starting at 1), skipping any
/// identifier that collides with a pinned share.
///
/// Constraints:
/// * `2 <= threshold <= limit`
/// * `fixed_shares.len() < threshold`
/// * All pinned identifiers distinct and non-zero
pub fn split_secret_with_fixed_shares<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    fixed_shares: &[S],
    rng: impl RngCore + CryptoRng,
) -> VsssResult<Vec<S>> {
    let generator = ParticipantIdGeneratorType::<S::Identifier>::default();
    split_secret_with_fixed_shares_and_participant_generator(
        threshold,
        limit,
        secret,
        fixed_shares,
        rng,
        &[generator],
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Variant of [`split_secret_with_fixed_shares`] that lets the caller
/// supply the participant identifier generator(s) used for non-pinned
/// shares. Same warnings apply.
pub fn split_secret_with_fixed_shares_and_participant_generator<S: Share>(
    threshold: usize,
    limit: usize,
    secret: &S::Value,
    fixed_shares: &[S],
    mut rng: impl RngCore + CryptoRng,
    participant_generators: &[ParticipantIdGeneratorType<S::Identifier>],
) -> VsssResult<Vec<S>> {
    check_params(threshold, limit)?;
    let k = fixed_shares.len();
    if k >= threshold || k > limit {
        return Err(Error::InvalidSizeRequest);
    }
    for (i, fs) in fixed_shares.iter().enumerate() {
        if fs.identifier().is_zero().into() {
            return Err(Error::SharingInvalidIdentifier);
        }
        for fs2 in fixed_shares.iter().skip(i + 1) {
            if fs.identifier() == fs2.identifier() {
                return Err(Error::SharingDuplicateIdentifier);
            }
        }
    }

    // q has (threshold - 1 - k) random coefficients. When k == threshold - 1
    // the polynomial is fully determined by the pinned points and the secret.
    let q_len = threshold - 1 - k;
    let mut q_coeffs: Vec<S::Identifier> = Vec::with_capacity(q_len);
    for _ in 0..q_len {
        q_coeffs.push(S::Identifier::random_coefficient(&mut rng));
    }

    let mut out: Vec<S> = Vec::with_capacity(limit);
    out.extend(fixed_shares.iter().cloned());

    let participant_id_collection = ParticipantIdGeneratorCollection::from(participant_generators);
    let mut id_iter = participant_id_collection.iter();
    while out.len() < limit {
        let id = id_iter.next().ok_or(Error::NotEnoughShareIdentifiers)?;
        if fixed_shares.iter().any(|fs| fs.identifier() == &id) {
            continue;
        }
        let value = eval_pinned_polynomial::<S>(secret, fixed_shares, &q_coeffs, &id)?;
        out.push(S::with_identifier_and_value(id, value));
    }
    Ok(out)
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn eval_pinned_polynomial<S: Share>(
    secret: &S::Value,
    fixed_shares: &[S],
    q_coeffs: &[S::Identifier],
    x: &S::Identifier,
) -> VsssResult<S::Value> {
    let mut acc = S::Value::default();

    // L_0(x) basis weight for the (0, secret) interpolation point:
    //   L_0(x) = Π_j (x - x_j) / (0 - x_j)
    {
        let mut num = S::Identifier::one();
        let mut den = S::Identifier::one();
        let zero = S::Identifier::zero();
        for fs in fixed_shares {
            let n = x.as_ref().clone() - fs.identifier().as_ref().clone();
            *num.as_mut() *= n;
            let d = zero.as_ref().clone() - fs.identifier().as_ref().clone();
            *den.as_mut() *= d;
        }
        let den_inv = den.invert()?;
        let basis_inner = num.as_ref().clone() * den_inv.as_ref().clone();
        let basis = S::Identifier::from(basis_inner);
        let term = secret.clone() * &basis;
        *acc.as_mut() += term.as_ref();
    }

    // L_i(x) basis weight for each pinned (x_i, y_i) point:
    //   L_i(x) = (x / x_i) · Π_{j != i} (x - x_j) / (x_i - x_j)
    for (i, pi) in fixed_shares.iter().enumerate() {
        let mut num = x.clone();
        let mut den = pi.identifier().clone();
        for (j, pj) in fixed_shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let n = x.as_ref().clone() - pj.identifier().as_ref().clone();
            *num.as_mut() *= n;
            let d = pi.identifier().as_ref().clone() - pj.identifier().as_ref().clone();
            *den.as_mut() *= d;
        }
        let den_inv = den.invert()?;
        let basis_inner = num.as_ref().clone() * den_inv.as_ref().clone();
        let basis = S::Identifier::from(basis_inner);
        let term = pi.value().clone() * &basis;
        *acc.as_mut() += term.as_ref();
    }

    // r(x) = x · Π(x - x_i) · q(x), q random of degree (threshold - 2 - k).
    // r vanishes at 0 and all pinned x_i, so adding it preserves the
    // pinning while injecting fresh entropy at non-pinned coordinates.
    if !q_coeffs.is_empty() {
        let mut van = x.clone();
        for fs in fixed_shares {
            let f = x.as_ref().clone() - fs.identifier().as_ref().clone();
            *van.as_mut() *= f;
        }
        let last = q_coeffs.len() - 1;
        let mut q_eval = q_coeffs[last].clone();
        for i in (0..last).rev() {
            *q_eval.as_mut() *= x.as_ref();
            *q_eval.as_mut() += q_coeffs[i].as_ref();
        }
        *van.as_mut() *= q_eval.as_ref();
        let r_val = S::Value::from(&van);
        *acc.as_mut() += r_val.as_ref();
    }

    Ok(acc)
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
mod fixed_share_tests {
    use super::*;
    use crate::{DefaultShare, IdentifierPrimeField, ReadableShareSet};
    use elliptic_curve::Field;
    use rand_core::OsRng;

    type S = DefaultShare<IdentifierPrimeField<k256::Scalar>, IdentifierPrimeField<k256::Scalar>>;

    #[test]
    fn pin_one_share_round_trip() {
        let mut rng = OsRng;
        let secret = IdentifierPrimeField(k256::Scalar::random(&mut rng));
        let split1 = split_secret::<S>(3, 5, &secret, &mut rng).unwrap();
        let pinned = split1[0].clone();

        let split2 = split_secret_with_fixed_shares::<S>(
            3,
            5,
            &secret,
            core::slice::from_ref(&pinned),
            &mut rng,
        )
        .unwrap();

        assert_eq!(split2[0], pinned, "pinned share preserved verbatim");
        assert_eq!(split2.len(), 5);
        // Recover from split 2 alone.
        assert_eq!(split2[..3].to_vec().combine().unwrap(), secret);
        // Mix pinned share with two fresh from split 2.
        let mixed = vec![pinned.clone(), split2[1].clone(), split2[2].clone()];
        assert_eq!(mixed.combine().unwrap(), secret);
    }

    #[test]
    fn pin_threshold_minus_one_is_deterministic() {
        let mut rng = OsRng;
        let secret = IdentifierPrimeField(k256::Scalar::random(&mut rng));
        let split1 = split_secret::<S>(3, 5, &secret, &mut rng).unwrap();
        // Pin 2 shares (= threshold - 1); polynomial fully determined.
        let pins: Vec<S> = vec![split1[0].clone(), split1[1].clone()];

        let split_a = split_secret_with_fixed_shares::<S>(3, 5, &secret, &pins, &mut rng).unwrap();
        let split_b = split_secret_with_fixed_shares::<S>(3, 5, &secret, &pins, &mut rng).unwrap();
        assert_eq!(split_a, split_b, "no entropy left, two calls match");
        assert_eq!(split_a, split1, "deterministic recovery of original split");
    }

    #[test]
    fn rejects_too_many_pins() {
        let mut rng = OsRng;
        let secret = IdentifierPrimeField(k256::Scalar::random(&mut rng));
        let split1 = split_secret::<S>(3, 5, &secret, &mut rng).unwrap();
        // Three pins for threshold=3 over-constrains.
        let pins: Vec<S> = vec![split1[0].clone(), split1[1].clone(), split1[2].clone()];
        let res = split_secret_with_fixed_shares::<S>(3, 5, &secret, &pins, &mut rng);
        assert_eq!(res.unwrap_err(), Error::InvalidSizeRequest);
    }

    #[test]
    fn rejects_zero_or_duplicate_pin_ids() {
        let mut rng = OsRng;
        let secret = IdentifierPrimeField(k256::Scalar::random(&mut rng));
        let zero = DefaultShare {
            identifier: IdentifierPrimeField(k256::Scalar::ZERO),
            value: IdentifierPrimeField(k256::Scalar::random(&mut rng)),
        };
        assert_eq!(
            split_secret_with_fixed_shares::<S>(3, 5, &secret, &[zero.clone()], &mut rng)
                .unwrap_err(),
            Error::SharingInvalidIdentifier
        );

        let split1 = split_secret::<S>(3, 5, &secret, &mut rng).unwrap();
        let dups = vec![split1[0].clone(), split1[0].clone()];
        assert_eq!(
            split_secret_with_fixed_shares::<S>(3, 5, &secret, &dups, &mut rng).unwrap_err(),
            Error::SharingDuplicateIdentifier
        );
    }
}
