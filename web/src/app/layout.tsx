import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import '../index.css'
import { Providers } from './providers'

export const metadata: Metadata = {
  title: 'zkCert',
  icons: '/favicon.svg',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
