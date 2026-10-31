import { BaseError, ContractFunctionRevertedError, type Client, type Hex } from 'viem'
import { readContract } from 'viem/actions'
import { decodePublicValues, type ProofBundle, type PublicValues } from './bundle'
import { ACCEPTED_VKEYS, KNOWN_KEYS, REGISTRY, SP1_GATEWAY } from './config'

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

/**
 * Verifies a bundle without trusting the server: an accepted (pinned) program vkey, and the SP1
 * Groth16 gateway via eth_call. The DKIM key allowlist is enforced inside the proof by each accepted
 * program version, so the key is only looked up here for display. Every check runs and is
 * reported, so a failure is explainable.
 */
export async function verifyBundle(b: ProofBundle, client: Client): Promise<Verdict> {
  const checks: Check[] = []
  const add = (label: string, ok: boolean, detail?: string) => (checks.push({ label, ok, detail }), ok)

  add('Real proof (Groth16)', b.proofSystem === 'groth16', b.proofSystem === 'mock' ? 'Mock bundle from a development prover: contains no proof.' : undefined)
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

  // The registry's owner may have retired a version this app still lists; Mint would then revert.
  if (REGISTRY) {
    try {
      const ok = await readContract(client, { address: REGISTRY, abi: registryAbi, functionName: 'acceptedVKeys', args: [b.vkey] })
      add('Registry accepts this program version', ok, ok ? undefined : 'Retired or never added on-chain (setVKey).')
    } catch (e) {
      add('Registry accepts this program version', false, reason(e))
    }
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

  return { valid: checks.every((c) => c.ok), checks, values, claimed, keyName }
}
