import { decodeAbiParameters, getAddress, type Address, type Hex } from 'viem'

/** The `zkcert-proof.json` format (script/src/bundle.rs). */
export type Decoded = {
  platform: string
  platformId: number
  courseHash: Hex
  courseName: string
  completedAt: number
  dkimKeyHash: Hex
  nullifier: Hex
  wallet: Address
}

export type ProofBundle = {
  version: string
  sp1Version: string
  proofSystem: 'groth16' | 'mock' | string
  vkey: Hex
  proof: Hex
  publicValues: Hex
  decoded: Decoded
}

export type PublicValues = {
  platform: number
  courseHash: Hex
  courseName: string
  completedAt: bigint
  dkimKeyHash: Hex
  nullifier: Hex
  wallet: Address
}

/** ABI of `PublicValues` (lib/src/lib.rs, contracts/src/ZkCertRegistry.sol). */
export const PUBLIC_VALUES_ABI = [
  {
    type: 'tuple',
    components: [
      { name: 'platform', type: 'uint8' },
      { name: 'courseHash', type: 'bytes32' },
      { name: 'courseName', type: 'string' },
      { name: 'completedAt', type: 'uint64' },
      { name: 'dkimKeyHash', type: 'bytes32' },
      { name: 'nullifier', type: 'bytes32' },
      { name: 'wallet', type: 'address' },
    ],
  },
] as const

export function decodePublicValues(hex: Hex): PublicValues {
  const [v] = decodeAbiParameters(PUBLIC_VALUES_ABI, hex)
  return { ...v, wallet: getAddress(v.wallet) }
}

const isHex = (x: unknown): x is Hex => typeof x === 'string' && /^0x[0-9a-fA-F]*$/.test(x)

/** Parses an uploaded file. Shape errors only; trust comes from verifyBundle. */
export function parseBundle(text: string): ProofBundle {
  let b: ProofBundle
  try {
    b = JSON.parse(text)
  } catch {
    throw new Error('Not a JSON file.')
  }
  if (b?.version !== 'zkcert-v1') throw new Error('Not a zkCert proof file (unknown version).')
  for (const k of ['vkey', 'proof', 'publicValues'] as const) {
    if (!isHex(b[k])) throw new Error(`Malformed proof file: "${k}" is not hex.`)
  }
  return b
}

export function summary(v: PublicValues, platformName: string): string {
  const course = v.courseName || '(course name hidden)'
  const when = v.completedAt > 0n ? ` on ${new Date(Number(v.completedAt) * 1000).toISOString().slice(0, 10)}` : ''
  return `zkCert: completed ${course} on ${platformName}${when}. Bound to ${v.wallet}.`
}

export function download(bundle: ProofBundle) {
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'zkcert-proof.json'
  a.click()
  URL.revokeObjectURL(url)
}
