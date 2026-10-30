import { useCallback, useEffect, useRef, useState } from 'react'
import { usePublicClient } from 'wagmi'
import { parseBundle, type ProofBundle } from '../lib/bundle'
import { REGISTRY } from '../lib/config'
import { verifyBundle, type Verdict } from '../lib/verify'
import { Claims } from './Claims'

/** `onLoad` shares a loaded file with the Mint tab. */
export function Verify({ initial, onLoad }: { initial: ProofBundle | null; onLoad: (b: ProofBundle) => void }) {
  const client = usePublicClient()
  const [bundle, setBundle] = useState<ProofBundle | null>(initial)
  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(initial !== null)
  const input = useRef<HTMLInputElement>(null)

  const run = useCallback(
    async (b: ProofBundle) => {
      if (!client) {
        setError('No RPC client for Base Sepolia.')
        setBusy(false)
        return
      }
      try {
        setVerdict(await verifyBundle(b, client))
      } catch (e) {
        setError(String(e))
      } finally {
        setBusy(false)
      }
    },
    [client],
  )

  // Verify the proof generated in this session when the tab opens.
  const started = useRef(false)
  useEffect(() => {
    if (initial && client && !started.current) {
      started.current = true
      void run(initial)
    }
  }, [initial, client, run])

  const load = async (f: File | undefined) => {
    if (!f) return
    setError(null)
    setVerdict(null)
    try {
      const b = parseBundle(await f.text())
      setBundle(b)
      onLoad(b)
      setBusy(true)
      await run(b)
    } catch (e) {
      setBundle(null)
      setError((e as Error).message)
    }
  }

  return (
    <section className="stack">
      <p className="muted">
        Checks run in your browser: the program vkey and DKIM key allowlist are pinned in this app, and the proof is verified by the SP1 verifier
        gateway on Base Sepolia with a read-only call. The prover server is not involved.
      </p>
      <div className="drop" onClick={() => input.current?.click()} role="button" tabIndex={0} onDragOver={(e) => e.preventDefault()} onDrop={(e) => (e.preventDefault(), load(e.dataTransfer.files[0]))}>
        <input ref={input} type="file" accept=".json,application/json" hidden onChange={(e) => load(e.target.files?.[0])} />
        <strong>{bundle ? 'Verify another proof file' : 'Drop a zkcert-proof.json'}</strong>
        <span className="muted">or click to choose</span>
      </div>
      {error && <p className="alert">{error}</p>}
      {busy && (
        <p className="muted">
          <span className="spinner" /> Verifying…
        </p>
      )}
      {verdict && (
        <div className={`card ${verdict.valid ? 'ok' : 'fail'}`}>
          <h3>{verdict.valid ? '✅ Valid certificate proof' : '❌ Not valid'}</h3>
          {verdict.values && <Claims v={verdict.values} />}
          <ul className="checks">
            {verdict.checks.map((c) => (
              <li key={c.label} className={c.ok ? 'pass' : 'failc'}>
                <span>{c.ok ? '✓' : '✗'}</span> {c.label}
                {c.detail && <small>{c.detail}</small>}
              </li>
            ))}
          </ul>
          {REGISTRY && verdict.claimed !== undefined && (
            <p className="muted">{verdict.claimed ? 'Already attested on-chain (nullifier used).' : 'Not yet attested on-chain.'}</p>
          )}
          {verdict.valid && (
            <p className="muted">
              A proof file can be copied. To know the presenter owns it, ask them to sign a message with the bound wallet, or check the on-chain
              attestation.
            </p>
          )}
        </div>
      )}
    </section>
  )
}
