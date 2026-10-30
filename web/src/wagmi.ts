import { http, createConfig } from 'wagmi'
import { baseSepolia } from 'wagmi/chains'
import { injected } from 'wagmi/connectors'

// Base Sepolia only: the SP1 Groth16 gateway and EAS (predeploy) both live there.
export const config = createConfig({
  ssr: true,
  chains: [baseSepolia],
  connectors: [injected()],
  transports: {
    [baseSepolia.id]: http(process.env.NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL || undefined),
  },
})

declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
