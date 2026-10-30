import { http, createConfig } from 'wagmi'
import { baseSepolia, sepolia } from 'wagmi/chains'

// Testnets only. RPC URLs fall back to the chains' public endpoints when unset.
export const config = createConfig({
  ssr: true,
  chains: [sepolia, baseSepolia],
  transports: {
    [sepolia.id]: http(process.env.NEXT_PUBLIC_SEPOLIA_RPC_URL),
    [baseSepolia.id]: http(process.env.NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL),
  },
})

declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
