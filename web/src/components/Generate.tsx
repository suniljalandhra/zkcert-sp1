import { useEffect, useRef, useState } from 'react'
import { isAddress } from 'viem'
import { useAccount } from 'wagmi'
import { decodePublicValues, download, summary, type Decoded, type ProofBundle } from '../lib/bundle'
import { API_URL, PLATFORMS } from '../lib/config'
import { Claims } from './Claims'
import { EmlHelp } from './EmlHelp'

type Phase =
  | { k: 'idle' }
  | { k: 'uploading' }
  | { k: 'queued' | 'proving'; jobId: string; preview: Decoded }
  | { k: 'done'; bundle: ProofBundle }
  | { k: 'error'; message: string; resume?: { jobId: string; preview: Decoded } }

// Server limit is 1 MiB for the whole multipart body; leave room for the other fields.
const MAX_BYTES = 1024 * 1024 - 4096

type ProofSystem = 'compressed' | 'groth16'
type Health = { proverKind: string; local: boolean; prover: string }

export function Generate({ onProof }: { onProof: (b: ProofBundle) => void }) {
  const { address } = useAccount()
  const [file, setFile] = useState<File | null>(null)
  // null = follow the connected wallet until the user types an address.
  const [walletInput, setWallet] = useState<string | null>(null)
  const wallet = walletInput ?? address ?? ''
  const [disclose, setDisclose] = useState(true)
  const [system, setSystem] = useState<ProofSystem>('compressed')
  const [health, setHealth] = useState<Health | null>(null)
  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth(null))
  }, [])
  // A local CPU prover runs out of memory on the Groth16 wrap on typical laptops.
  const groth16Ok = health !== null && health.proverKind !== 'cpu'
  const [phase, setPhase] = useState<Phase>({ k: 'idle' })
  const [copied, setCopied] = useState(false)
  const [drag, setDrag] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  const jobId = phase.k === 'queued' || phase.k === 'proving' ? phase.jobId : null
  useEffect(() => {
    if (!jobId) return
    let stop = false
    let failures = 0
    const tick = async () => {
      try {
        const r = await fetch(`${API_URL}/prove/${jobId}`)
        const j = await r.json()
        if (stop) return
        if (!r.ok) return setPhase({ k: 'error', message: j.error ?? 'Job not found (the server may have restarted).' })
        if (j.status === 'done') {
          setPhase({ k: 'done', bundle: j.bundle })
          onProof(j.bundle)
          return
        }
        if (j.status === 'failed') return setPhase({ k: 'error', message: j.error })
        failures = 0
        setPhase((p) => (p.k === 'queued' || p.k === 'proving' ? { ...p, k: j.status } : p))
      } catch {
        // Ride out short network blips; after that keep the job id so the user can resume.
        if (stop) return
        if (++failures >= 5) {
          return setPhase((p) =>
            p.k === 'queued' || p.k === 'proving'
              ? { k: 'error', message: 'Lost contact with the prover server.', resume: { jobId: p.jobId, preview: p.preview } }
              : p,
          )
        }
      }
      if (!stop) setTimeout(tick, 3000)
    }
    tick()
    return () => {
      stop = true
    }
  }, [jobId, onProof])

  const pick = (f: File | undefined) => {
    if (!f) return
    if (f.size > MAX_BYTES) return setPhase({ k: 'error', message: 'File is larger than 1 MB; that is not a completion email.' })
    setFile(f)
    setPhase({ k: 'idle' })
  }

  const submit = async () => {
    if (!file || !isAddress(wallet)) return
    setPhase({ k: 'uploading' })
    const form = new FormData()
    form.append('eml', file)
    form.append('wallet', wallet)
    form.append('disclose', String(disclose))
    form.append('proofSystem', system)
    try {
      const r = await fetch(`${API_URL}/prove`, { method: 'POST', body: form })
      const j = await r.json().catch(() => ({}))
      if (r.status === 413) return setPhase({ k: 'error', message: 'File too large.' })
      if (!r.ok) return setPhase({ k: 'error', message: j.error ?? `Server error ${r.status}` })
      setPhase({ k: 'queued', jobId: j.jobId, preview: j.preview })
    } catch {
      setPhase({ k: 'error', message: `Cannot reach the prover server at ${API_URL}. Is it running?` })
    }
  }

  const busy = phase.k === 'uploading' || phase.k === 'queued' || phase.k === 'proving'
  const walletOk = isAddress(wallet)

  return (
    <section className="stack">
      <div
        className={`drop ${drag ? 'drag' : ''} ${file ? 'has' : ''}`}
        onClick={() => input.current?.click()}
        onDragOver={(e) => (e.preventDefault(), setDrag(true))}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => (e.preventDefault(), setDrag(false), pick(e.dataTransfer.files[0]))}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && input.current?.click()}
      >
        <input ref={input} type="file" accept=".eml,message/rfc822" hidden onChange={(e) => pick(e.target.files?.[0])} />
        {file ? (
          <>
            <strong>{file.name}</strong>
            <span className="muted">{(file.size / 1024).toFixed(1)} KB · click to change</span>
          </>
        ) : (
          <>
            <strong>Drop your completion email (.eml)</strong>
            <span className="muted">Coursera “Your Certificate is Ready” or Udemy “Your completion certificate is ready”</span>
          </>
        )}
      </div>
      <EmlHelp />

      <label className="field">
        <span>Wallet</span>
        <input value={wallet} onChange={(e) => setWallet(e.target.value.trim())} placeholder="0x…" spellCheck={false} />
        {wallet && !walletOk && <small className="bad">Not a valid address.</small>}
      </label>

      <label className="check">
        <input type="checkbox" checked={disclose} onChange={(e) => setDisclose(e.target.checked)} />
        <span>Show the course name (otherwise only its hash)</span>
      </label>

      <fieldset className="choice">
        <legend>Proof type</legend>
        <label className="check">
          <input type="radio" name="system" checked={system === 'compressed'} onChange={() => setSystem('compressed')} />
          <span>
            <strong>Off-chain</strong> · verified in any browser
          </span>
        </label>
        <label className="check">
          <input type="radio" name="system" checked={system === 'groth16'} disabled={!groth16Ok} onChange={() => setSystem('groth16')} />
          <span>
            <strong>On-chain</strong> · Groth16, mintable {!groth16Ok && <span className="muted">(needs SP1_PROVER=network)</span>}
          </span>
        </label>
      </fieldset>

      {health ? (
        health.local ? (
          <p className="note">Proving runs on this machine. Your email never leaves it.</p>
        ) : (
          <p className="alert">
            Proving uses Succinct&apos;s prover network, which receives your email.
          </p>
        )
      ) : (
        <p className="muted">Prover server not reachable at {API_URL}.</p>
      )}

      <button className="primary" disabled={!file || !walletOk || busy} onClick={submit}>
        {busy ? 'Working…' : 'Generate proof'}
      </button>

      {phase.k === 'uploading' && <p className="muted">Checking the DKIM signature…</p>}
      {(phase.k === 'queued' || phase.k === 'proving') && (
        <div className="card">
          <p>
            <span className="spinner" /> {phase.k === 'queued'
              ? 'Signature valid. Waiting for the prover…'
              : system === 'compressed'
                ? 'Proving (about 1–2 minutes)…'
                : 'Proving Groth16 (several minutes)…'}
          </p>
          <p className="muted">
            Detected: {phase.preview.platform} · {phase.preview.courseName || 'course hidden'}
          </p>
        </div>
      )}
      {phase.k === 'error' && (
        <div className="stack">
          <p className="alert">{phase.message}</p>
          {phase.resume && (
            <button onClick={() => phase.resume && setPhase({ k: 'proving', ...phase.resume })}>Resume checking job</button>
          )}
        </div>
      )}
      {phase.k === 'done' && <Done bundle={phase.bundle} copied={copied} setCopied={setCopied} />}
    </section>
  )
}

function Done({ bundle, copied, setCopied }: { bundle: ProofBundle; copied: boolean; setCopied: (b: boolean) => void }) {
  const v = decodePublicValues(bundle.publicValues)
  const text = summary(v, PLATFORMS[v.platform] ?? 'unknown platform')
  return (
    <div className="card ok">
      <h3>Proof ready</h3>
      {bundle.proofSystem === 'mock' && <p className="alert">Development mock: this file contains no real proof and will not verify.</p>}
      <Claims v={v} />
      <div className="row">
        <button className="primary" onClick={() => download(bundle)}>Download zkcert-proof.json</button>
        <button onClick={() => navigator.clipboard.writeText(text).then(() => setCopied(true))}>{copied ? 'Copied' : 'Copy summary'}</button>
      </div>
      <p className="muted">
        The prover has dropped your email. Keep the proof file{bundle.proofSystem === 'compressed' ? ` (${(bundle.proof.length / 2 / 1e6).toFixed(1)} MB)` : ''}; anyone can
        verify it in the Verify tab.
      </p>
    </div>
  )
}
