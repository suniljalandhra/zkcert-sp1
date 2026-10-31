# fixtures/

Real completion emails are personal data. Everything in this folder is git-ignored except this
README and `redacted/` (samples whose personal fields have been removed and reviewed).

## Getting a `.eml`
Gmail: open the Coursera/Udemy completion email → ⋮ (More) → **Download message**.
Copy it here, e.g. `fixtures/udemy.eml`. Do not edit it: any change breaks the DKIM signature.

## `redacted/`
`synthetic-udemy.eml` is a made-up Udemy email signed with a throwaway RSA key (`zkcert synth`);
`synthetic-udemy.key` is that key's public DKIM record. The key is not in the guest's key table
(`lib/src/keys.rs`), so the program rejects this email: it is the "attacker's own key" demo
(`zkcert execute ... --key test._domainkey.e.udemymail.com=fixtures/redacted/synthetic-udemy.key --no-host-check`).
The contract fixture must therefore be a proof of a real email (see README, "Real Groth16 fixture").
