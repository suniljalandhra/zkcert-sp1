# fixtures/

Put your own `.eml` files here; they are git-ignored. In Gmail: open the email → ⋮ → **Download message**.
Don't edit or forward them, or the DKIM signature breaks.

`redacted/synthetic-udemy.eml` is a fake email signed with a throwaway key (`zkcert synth`). The program
rejects it because that key isn't in `lib/src/keys.rs`; it's the "attacker's own key" example.
