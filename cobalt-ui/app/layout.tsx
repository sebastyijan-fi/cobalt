import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Cobalt Enterprise Audit',
  description: 'Cryptographic Chain-of-Custody infrastructure for AI and Compliance.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-slate-950 text-slate-50 min-h-screen selection:bg-indigo-500/30`}>
        <div className="flex h-screen overflow-hidden">
          {children}
        </div>
      </body>
    </html>
  )
}
