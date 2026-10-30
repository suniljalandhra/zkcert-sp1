# fixtures/

Real completion emails are personal data. Everything in this folder is git-ignored except this
README and `redacted/` (samples whose personal fields have been removed and reviewed).

## Getting a `.eml`
Gmail: open the Coursera/Udemy completion email → ⋮ (More) → **Download message**.
Copy it here, e.g. `fixtures/udemy.eml`. Do not edit it: any change breaks the DKIM signature.

## `redacted/`
`synthetic-udemy.eml` is a made-up Udemy email signed with a throwaway RSA key (`zkcert synth`);
`synthetic-udemy.key` is that key's public DKIM record. The committed contract fixture
(`contracts/src/fixtures/groth16-proof.json`) is a real Groth16 proof of this email. The key is not on
the production allowlist, so this proof is only accepted by tests that allowlist it explicitly.
