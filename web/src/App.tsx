'use client'

import { useCallback, useState } from 'react'
import { useAccount, useConnect, useDisconnect } from 'wagmi'
import { Generate } from './components/Generate'
import { Mint } from './components/Mint'
import { Verify } from './components/Verify'
import type { ProofBundle } from './lib/bundle'

const TABS = ['Generate', 'Verify', 'Mint'] as const
type Tab = (typeof TABS)[number]

function WalletButton() {
  const { address, isConnected } = useAccount()
  const { connect, connectors, error } = useConnect()
  const { disconnect } = useDisconnect()
  if (isConnected) {
    return (
      <button className="ghost" onClick={() => disconnect()} title="Disconnect">
        {address?.slice(0, 6)}…{address?.slice(-4)}
      </button>
    )
  }
  const c = connectors[0]
  return (
    <div className="wallet">
      <button className="ghost" onClick={() => connect({ connector: c })}>
        Connect wallet
      </button>
      {error && <small className="bad">{error.message.includes('Provider not found') ? 'No browser wallet found.' : error.message}</small>}
    </div>
  )
}

export default function App() {
  const [tab, setTab] = useState<Tab>('Generate')
  const [bundle, setBundle] = useState<ProofBundle | null>(null)
  const onProof = useCallback((b: ProofBundle) => setBundle(b), [])

  return (
    <main>
      <header>
        <div>
          <h1>zkCert</h1>
          <p className="muted">Prove a Coursera or Udemy certificate from its signed email, without revealing the email.</p>
        </div>
        <WalletButton />
      </header>
      <nav role="tablist">
        {TABS.map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </nav>
      <div hidden={tab !== 'Generate'}>
        <Generate onProof={onProof} />
      </div>
      {tab === 'Verify' && <Verify initial={bundle} onLoad={onProof} />}
      {tab === 'Mint' && <Mint bundle={bundle} />}
      <footer className="muted">
        SP1 zkVM · DKIM (RFC 6376)
      </footer>
    </main>
  )
}
