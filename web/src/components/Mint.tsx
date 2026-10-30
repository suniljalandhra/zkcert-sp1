import { useState } from 'react'
import { decodeEventLog, type Hex } from 'viem'
import { baseSepolia } from 'viem/chains'
import { useAccount, useConnect, usePublicClient, useSwitchChain, useWriteContract } from 'wagmi'
import { decodePublicValues, type ProofBundle } from '../lib/bundle'
import { REGISTRY } from '../lib/config'
import { reason, registryAbi } from '../lib/verify'

type State = { k: 'idle' } | { k: 'pending'; msg: string } | { k: 'done'; tx: Hex; uid?: Hex } | { k: 'error'; msg: string }

export function Mint({ bundle }: { bundle: ProofBundle | null }) {
  const { address, chainId, isConnected } = useAccount()
  const { connect, connectors, error: connectError } = useConnect()
  const { switchChainAsync } = useSwitchChain()
  const { writeContractAsync } = useWriteContract()
  const client = usePublicClient()
  const [state, setState] = useState<State>({ k: 'idle' })

  if (!REGISTRY) {
    return (
      <section className="stack">
        <p className="muted">
          Minting is optional and needs a deployed ZkCertRegistry. Deploy it (see README) and set <code>NEXT_PUBLIC_REGISTRY_ADDRESS</code>.
        </p>
      </section>
    )
  }
  if (!bundle) return <p className="muted">Generate a proof first, or load one in the Verify tab.</p>

  const registry = REGISTRY
  const v = decodePublicValues(bundle.publicValues)
  const wrongWallet = isConnected && address?.toLowerCase() !== v.wallet.toLowerCase()

  const mint = async () => {
    try {
      if (chainId !== baseSepolia.id) {
        setState({ k: 'pending', msg: 'Switching to Base Sepolia…' })
        await switchChainAsync({ chainId: baseSepolia.id })
      }
      setState({ k: 'pending', msg: 'Simulating…' })
      await client!.simulateContract({ address: registry, abi: registryAbi, functionName: 'claim', args: [bundle.publicValues, bundle.proof], account: address })
      setState({ k: 'pending', msg: 'Confirm in your wallet…' })
      const tx = await writeContractAsync({ address: registry, abi: registryAbi, functionName: 'claim', args: [bundle.publicValues, bundle.proof], chainId: baseSepolia.id })
      setState({ k: 'pending', msg: 'Waiting for confirmation…' })
      const receipt = await client!.waitForTransactionReceipt({ hash: tx })
      if (receipt.status !== 'success') throw new Error('Transaction reverted.')
      let uid: Hex | undefined
      for (const log of receipt.logs.filter((l) => l.address.toLowerCase() === registry.toLowerCase())) {
        try {
          const e = decodeEventLog({ abi: registryAbi, ...log })
          if (e.eventName === 'Claimed') uid = e.args.uid
        } catch {
          /* other contracts' logs */
        }
      }
      setState({ k: 'done', tx, uid })
    } catch (e) {
      setState({ k: 'error', msg: reason(e) })
    }
  }

  return (
    <section className="stack">
      <p className="muted">
        Records the certificate as an EAS attestation to the bound wallet. The registry verifies the proof again, checks the key allowlist, and that
        this certificate (nullifier) was not claimed before. The recipient wallet becomes public on-chain.
      </p>
      <p>
        Bound wallet: <span className="mono">{v.wallet}</span>
      </p>
      {bundle.proofSystem !== 'groth16' && <p className="alert">This bundle has no real proof (mock); it cannot be minted.</p>}
      {!isConnected ? (
        <div className="row">
          {connectors.map((c) => (
            <button key={c.uid} className="primary" onClick={() => connect({ connector: c })}>
              Connect {c.name}
            </button>
          ))}
          {connectError && <p className="alert">{connectError.message}</p>}
        </div>
      ) : wrongWallet ? (
        <p className="alert">Connected wallet {address} is not the bound wallet. Switch accounts in your wallet.</p>
      ) : (
        <button className="primary" disabled={state.k === 'pending' || bundle.proofSystem !== 'groth16'} onClick={mint}>
          Mint attestation on Base Sepolia
        </button>
      )}
      {state.k === 'pending' && (
        <p className="muted">
          <span className="spinner" /> {state.msg}
        </p>
      )}
      {state.k === 'error' && <p className="alert">{state.msg}</p>}
      {state.k === 'done' && (
        <div className="card ok">
          <p>Attested.</p>
          <p>
            <a href={`https://sepolia.basescan.org/tx/${state.tx}`} target="_blank" rel="noreferrer">View transaction</a>
            {state.uid && (
              <>
                {' · '}
                <a href={`https://base-sepolia.easscan.org/attestation/view/${state.uid}`} target="_blank" rel="noreferrer">View on EAS</a>
              </>
            )}
          </p>
        </div>
      )}
    </section>
  )
}
