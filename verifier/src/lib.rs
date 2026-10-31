//! Verification of zkCert proofs in SP1's "compressed" mode: a STARK that can be checked off-chain
//! in milliseconds, without the Groth16 wrap (which needs far more memory to produce).
//!
//! The proof is checked against the program's KoalaBear vkey digest. That digest maps one-to-one
//! to the `bytes32` vkey used everywhere else (config/program.json, the registry), so callers get
//! the `bytes32` back and must check it is an accepted program version.

use slop_algebra::PrimeField32;
use sp1_primitives::SP1Field;
use sp1_verifier::compressed::SP1CompressedVerifierRaw;

/// `bytes32` vkey (`0x`-prefixed, 64 hex digits) of a bincode-encoded `[SP1Field; 8]` vkey digest.
///
/// Same value as sp1-sdk's `HashableKey::bytes32`: the eight 31-bit field elements are packed
/// big-endian into one integer (`koalabears_to_bn254` in sp1-hypercube). 8 × 31 = 248 bits stays
/// below the BN254 modulus, so no reduction happens and the packing is injective.
pub fn vkey_bytes32(vkey_hash: &[u8]) -> Result<String, String> {
    let digest: [SP1Field; 8] =
        bincode::deserialize(vkey_hash).map_err(|e| format!("vkey hash: {e}"))?;
    // 256-bit big-endian accumulator in four u64 limbs (limbs[0] most significant).
    let mut limbs = [0u64; 4];
    for word in digest {
        let mut carry = word.as_canonical_u32() as u64;
        for limb in limbs.iter_mut().rev() {
            let wide = ((*limb as u128) << 31) | carry as u128;
            *limb = wide as u64;
            carry = (wide >> 64) as u64;
        }
    }
    Ok(format!(
        "0x{}",
        limbs
            .iter()
            .map(|l| format!("{l:016x}"))
            .collect::<String>()
    ))
}

/// Verifies a compressed proof (bincode `SP1Proof`) for `public_values` under `vkey_hash`.
/// Returns the program's `bytes32` vkey, which the caller must find in its accepted set.
pub fn verify_compressed(
    proof: &[u8],
    public_values: &[u8],
    vkey_hash: &[u8],
) -> Result<String, String> {
    let vkey = vkey_bytes32(vkey_hash)?;
    SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, vkey_hash)
        .map_err(|e| e.to_string())?;
    Ok(vkey)
}

#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Browser entry point; see [`super::verify_compressed`].
    #[wasm_bindgen(js_name = verifyCompressed)]
    pub fn verify_compressed(
        proof: &[u8],
        public_values: &[u8],
        vkey_hash: &[u8],
    ) -> Result<String, JsError> {
        super::verify_compressed(proof, public_values, vkey_hash).map_err(|e| JsError::new(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::AbstractField;

    fn f(x: u32) -> SP1Field {
        SP1Field::from_canonical_u32(x)
    }

    #[test]
    fn packs_digest_big_endian() {
        let mut d = [f(0); 8];
        d[6] = f(1);
        d[7] = f(5);
        let v = vkey_bytes32(&bincode::serialize(&d).unwrap()).unwrap();
        assert_eq!(v, format!("0x{:064x}", (1u64 << 31) | 5));
        // The top word lands at bit 7 * 31 = 217.
        let mut top = [f(0); 8];
        top[0] = f(1);
        let v = vkey_bytes32(&bincode::serialize(&top).unwrap()).unwrap();
        // 2^217 = 2 * 16^54: hex "2" followed by 54 zeros.
        assert_eq!(v, format!("0x{:0>64}", format!("2{}", "0".repeat(54))));
    }

    #[test]
    fn rejects_garbage() {
        assert!(vkey_bytes32(&[1, 2, 3]).is_err());
        let d = bincode::serialize(&[f(1); 8]).unwrap();
        assert!(verify_compressed(b"not a proof", b"", &d).is_err());
    }
}
