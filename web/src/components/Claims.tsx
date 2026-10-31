import type { PublicValues } from '../lib/bundle'
import { PLATFORMS } from '../lib/config'

const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`

export function Claims({ v }: { v: PublicValues }) {
  const date = v.emailSignedAt > 0n ? new Date(Number(v.emailSignedAt) * 1000).toISOString().slice(0, 10) : 'no signing time from this platform'
  return (
    <dl className="claims">
      <dt>Platform</dt>
      <dd>{PLATFORMS[v.platform] ?? `unknown (${v.platform})`}</dd>
      <dt>Course</dt>
      <dd>{v.courseName || <span className="muted">hidden (hash {short(v.courseHash)})</span>}</dd>
      <dt>Email signed</dt>
      <dd>{date}</dd>
      <dt>Bound wallet</dt>
      <dd className="mono">{v.wallet}</dd>
      <dt>Nullifier</dt>
      <dd className="mono">{short(v.nullifier)}</dd>
    </dl>
  )
}
