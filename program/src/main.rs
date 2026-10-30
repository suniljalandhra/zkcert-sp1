//! zkCert guest: proves that a Coursera/Udemy completion email carries a valid DKIM signature
//! and commits only the facts in `PublicValues`. All logic lives in `zkcert_lib::verify` so the
//! host can run the identical checks before proving.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zkcert_lib::{
    verify::{verify, GuestInput},
    PublicValues,
};

pub fn main() {
    let input = sp1_zkvm::io::read::<GuestInput>();
    let values = verify(&input).unwrap_or_else(|e| panic!("zkcert: {e}"));
    sp1_zkvm::io::commit_slice(&PublicValues::abi_encode(&values));
}
