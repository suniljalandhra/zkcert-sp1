import { fileURLToPath } from 'node:url'
import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // Static export: the app runs entirely in the browser, with no Next.js server.
  output: 'export',
  // The DKIM key allowlist and program vkey live in ../config, shared with Rust and Solidity.
  turbopack: { root: fileURLToPath(new URL('..', import.meta.url)) },
}

export default nextConfig
