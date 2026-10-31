// The SP1 compressed-proof verifier (verifier/ crate) compiled to WebAssembly by build-wasm.sh.
// Loaded on first use so the 1 MB module is not part of the initial page load.
let ready: Promise<typeof import('../wasm/zkcert_verifier.js')> | null = null

function load() {
  ready ??= import('../wasm/zkcert_verifier.js').then(async (m) => {
    await m.default()
    return m
  })
  return ready
}

/** Verifies a compressed proof in the browser. Returns the program's bytes32 vkey; throws if invalid. */
export async function verifyCompressed(proof: Uint8Array, publicValues: Uint8Array, vkeyHash: Uint8Array): Promise<string> {
  const m = await load()
  return m.verifyCompressed(proof, publicValues, vkeyHash)
}
