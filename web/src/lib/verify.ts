import { BaseError, ContractFunctionRevertedError, hexToBytes, type Client, type Hex } from 'viem'
import { readContract } from 'viem/actions'
import { decodePublicValues, type ProofBundle, type PublicValues } from './bundle'
import { ACCEPTED_VKEYS, KNOWN_KEYS, REGISTRY, SP1_GATEWAY } from './config'
import { verifyCompressed } from './wasm'

export type Check = { label: string; ok: boolean; detail?: string }
export type Verdict = { valid: boolean; checks: Check[]; values?: PublicValues; claimed?: boolean; keyName?: string }

const gatewayAbi = [
  {
    type: 'function',
    name: 'verifyProof',
    stateMutability: 'view',
    inputs: [
      { name: 'programVKey', type: 'bytes32' },
      { name: 'publicValues', type: 'bytes' },
      { name: 'proofBytes', type: 'bytes' },
    ],
    outputs: [],
  },
] as const

export const registryAbi = [
  {
    type: 'function',
    name: 'acceptedVKeys',
    stateMutability: 'view',
    inputs: [{ name: 'vkey', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'function',
    name: 'claimed',
    stateMutability: 'view',
    inputs: [{ name: 'nullifier', type: 'bytes32' }],
    outputs: [{ type: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'claim',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'vkey', type: 'bytes32' },
      { name: 'publicValues', type: 'bytes' },
      { name: 'proof', type: 'bytes' },
    ],
    outputs: [{ name: 'uid', type: 'bytes32' }],
  },
  {
    type: 'event',
    name: 'Claimed',
    inputs: [
      { name: 'nullifier', type: 'bytes32', indexed: true },
      { name: 'wallet', type: 'address', indexed: true },
      { name: 'platform', type: 'uint8', indexed: false },
      { name: 'courseHash', type: 'bytes32', indexed: false },
      { name: 'programVKey', type: 'bytes32', indexed: false },
      { name: 'uid', type: 'bytes32', indexed: false },
    ],
  },
  { type: 'error', name: 'UnknownProgram', inputs: [{ type: 'bytes32' }] },
  { type: 'error', name: 'WrongWallet', inputs: [{ type: 'address' }, { type: 'address' }] },
  { type: 'error', name: 'AlreadyClaimed', inputs: [{ type: 'bytes32' }, { type: 'bytes32' }] },
] as const

export function reason(e: unknown): string {
  if (e instanceof BaseError) {
    const revert = e.walk((x) => x instanceof ContractFunctionRevertedError)
    if (revert instanceof ContractFunctionRevertedError) {
      const name = revert.data?.errorName
      if (name === 'WrongWallet') return 'Connected wallet is not the wallet bound in this proof.'
      if (name === 'AlreadyClaimed') return 'This certificate has already been claimed (nullifier used).'
      if (name === 'UnknownProgram') return 'The registry does not accept this program version (vkey).'
      return name ? `Reverted: ${name}` : 'The verifier rejected the proof.'
    }
    return e.shortMessage
  }
  return e instanceof Error ? e.message : String(e)
}

/** Verifies a bundle without trusting the server: compressed proofs in WebAssembly, Groth16 via the SP1 gateway. */
export async function verifyBundle(b: ProofBundle, client?: Client): Promise<Verdict> {
  const checks: Check[] = []
  const add = (label: string, ok: boolean, detail?: string) => (checks.push({ label, ok, detail }), ok)

  const real = b.proofSystem === 'compressed' || b.proofSystem === 'groth16'
  add(
    'Real proof (not a development mock)',
    real,
    b.proofSystem === 'mock' ? 'Mock bundle from a development prover: contains no proof.' : real ? b.proofSystem : `Unknown proof type ${b.proofSystem}`,
  )
  const vkeyOk = ACCEPTED_VKEYS.includes(b.vkey.toLowerCase() as Hex)
  add('Proof is for an accepted zkCert program version (vkey)', vkeyOk, vkeyOk ? undefined : `vkey ${b.vkey} is not an accepted version`)

  let values: PublicValues | undefined
  try {
    values = decodePublicValues(b.publicValues)
    add('Public values decode', true)
  } catch {
    add('Public values decode', false, 'publicValues is not a zkCert PublicValues encoding.')
  }

  // Display only: the proof already rejected any key outside the program's table.
  const keyName = values && KNOWN_KEYS.find((k) => k.keyHash === values!.dkimKeyHash.toLowerCase() && k.platform === values!.platform)?.name

  if (b.proofSystem === 'groth16') {
    if (!client) {
      add('SP1 proof verifies on-chain (Base Sepolia gateway, eth_call)', false, 'No RPC client for Base Sepolia.')
    } else {
      try {
        await readContract(client, {
          address: SP1_GATEWAY,
          abi: gatewayAbi,
          functionName: 'verifyProof',
          args: [b.vkey, b.publicValues, b.proof as Hex],
        })
        add('SP1 proof verifies on-chain (Base Sepolia gateway, eth_call)', true)
      } catch (e) {
        add('SP1 proof verifies on-chain (Base Sepolia gateway, eth_call)', false, reason(e))
      }
    }
  } else if (b.proofSystem === 'compressed') {
    const label = 'SP1 proof verifies in this browser (WebAssembly, no network)'
    try {
      if (!b.vkeyHash) throw new Error('The file has no vkeyHash.')
      const t = performance.now()
      const vkey = await verifyCompressed(hexToBytes(b.proof), hexToBytes(b.publicValues), hexToBytes(b.vkeyHash))
      // The proof was checked against vkeyHash, so that must be the vkey accepted above.
      if (vkey.toLowerCase() !== b.vkey.toLowerCase()) throw new Error(`vkeyHash is for program ${vkey}, not ${b.vkey}.`)
      add(label, true, `${Math.round(performance.now() - t)} ms`)
    } catch (e) {
      add(label, false, e instanceof Error ? e.message : String(e))
    }
  }

  // The registry's owner may have retired a version this app still lists; Mint would then revert.
  if (REGISTRY && client && b.proofSystem === 'groth16') {
    try {
      const ok = await readContract(client, { address: REGISTRY, abi: registryAbi, functionName: 'acceptedVKeys', args: [b.vkey] })
      add('Registry accepts this program version', ok, ok ? undefined : 'Retired or never added on-chain (setVKey).')
    } catch (e) {
      add('Registry accepts this program version', false, reason(e))
    }
  }

  let claimed: boolean | undefined
  if (values && REGISTRY && client && b.proofSystem === 'groth16') {
    try {
      const uid = await readContract(client, { address: REGISTRY, abi: registryAbi, functionName: 'claimed', args: [values.nullifier] })
      claimed = BigInt(uid) !== 0n
    } catch {
      claimed = undefined
    }
  }

  return { valid: checks.every((c) => c.ok), checks, values, claimed, keyName }
}
