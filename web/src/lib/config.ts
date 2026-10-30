import { getAddress, type Address, type Hex } from 'viem'
import allowlist from '../../../config/dkim-keys.json'
import program from '../../../config/program.json'

export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8080'

/** SP1 Groth16 verifier gateway on Base Sepolia (sp1-contracts deployments/84532.json). */
export const SP1_GATEWAY: Address = '0x397A5f7f3dBd538f23DE225B51f532c34448dA9B'

/** The zkCert program this UI accepts. Pinned in the repo, never fetched from the server. */
export const PROGRAM_VKEY = program.vkey.toLowerCase() as Hex

export const REGISTRY: Address | undefined = process.env.NEXT_PUBLIC_REGISTRY_ADDRESS
  ? getAddress(process.env.NEXT_PUBLIC_REGISTRY_ADDRESS)
  : undefined

export type KnownKey = { platform: number; name: string; keyHash: Hex }

export const KNOWN_KEYS: KnownKey[] = allowlist.keys.map((k) => ({
  platform: k.platform,
  name: k.name,
  keyHash: k.keyHash.toLowerCase() as Hex,
}))

export const PLATFORMS: Record<number, string> = { 1: 'Coursera', 2: 'Udemy' }
