import { BaseError, ContractFunctionRevertedError, type Client, type Hex } from 'viem'
import { readContract } from 'viem/actions'
import { decodePublicValues, type ProofBundle, type PublicValues } from './bundle'
import { KNOWN_KEYS, PLATFORMS, PROGRAM_VKEY, REGISTRY, SP1_GATEWAY } from './config'

export type Check = { label: string; ok: boolean; detail?: string }
export type Verdict = { valid: boolean; checks: Check[]; values?: PublicValues; claimed?: boolean }

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
      { name: 'uid', type: 'bytes32', indexed: false },
    ],
  },
  { type: 'error', name: 'UnknownKey', inputs: [{ type: 'bytes32' }, { type: 'uint8' }] },
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
      if (name === 'UnknownKey') return 'DKIM key is not on the registry allowlist.'
      return name ? `Reverted: ${name}` : 'The verifier rejected the proof.'
    }
    return e.shortMessage
  }
  return e instanceof Error ? e.message : String(e)
}

/**
 * Verifies a bundle without trusting the server: pinned vkey, pinned key allowlist, and the SP1
 * Groth16 gateway via eth_call. Every check runs and is reported, so a failure is explainable.
 */
export async function verifyBundle(b: ProofBundle, client: Client): Promise<Verdict> {
  const checks: Check[] = []
  const add = (label: string, ok: boolean, detail?: string) => (checks.push({ label, ok, detail }), ok)

  add('Real proof (Groth16)', b.proofSystem === 'groth16', b.proofSystem === 'mock' ? 'Mock bundle from a development prover: contains no proof.' : undefined)
  add('Proof is for the zkCert program (vkey)', b.vkey.toLowerCase() === PROGRAM_VKEY, b.vkey.toLowerCase() === PROGRAM_VKEY ? undefined : `vkey ${b.vkey} ≠ ${PROGRAM_VKEY}`)

  let values: PublicValues | undefined
  try {
    values = decodePublicValues(b.publicValues)
    add('Public values decode', true)
  } catch {
    add('Public values decode', false, 'publicValues is not a zkCert PublicValues encoding.')
  }

  if (values) {
    const key = KNOWN_KEYS.find((k) => k.keyHash === values!.dkimKeyHash.toLowerCase())
    const keyOk = !!key && key.platform === values.platform
    add(
      `DKIM key is a known ${PLATFORMS[values.platform] ?? 'platform'} key`,
      keyOk,
      key ? (keyOk ? key.name : `${key.name} belongs to another platform`) : `unknown key ${values.dkimKeyHash}`,
    )
  }

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

  let claimed: boolean | undefined
  if (values && REGISTRY) {
    try {
      const uid = await readContract(client, { address: REGISTRY, abi: registryAbi, functionName: 'claimed', args: [values.nullifier] })
      claimed = BigInt(uid) !== 0n
    } catch {
      claimed = undefined
    }
  }

  return { valid: checks.every((c) => c.ok), checks, values, claimed }
}
